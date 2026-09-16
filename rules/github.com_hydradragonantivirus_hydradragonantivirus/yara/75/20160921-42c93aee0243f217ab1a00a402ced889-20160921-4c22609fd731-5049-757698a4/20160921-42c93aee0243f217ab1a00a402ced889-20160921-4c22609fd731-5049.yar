rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_4c22609fd731_5049 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_4c22609fd7310d7f415ca007620a244b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"

  strings:
    $s1 = "n \"Vu\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2 = " \"DNa\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s3 = ",(function f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TKp\";})(),(function f000()" ascii
    $s4 = "Dg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(functio" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wy\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}