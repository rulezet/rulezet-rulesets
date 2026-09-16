rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_6d18600f3019_4543 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"

  strings:
    $s1 = "eturn \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s2 = "0(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";" ascii
    $s3 = "rn \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(fun" ascii
    $s4 = "unction f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s5 = "tion f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}