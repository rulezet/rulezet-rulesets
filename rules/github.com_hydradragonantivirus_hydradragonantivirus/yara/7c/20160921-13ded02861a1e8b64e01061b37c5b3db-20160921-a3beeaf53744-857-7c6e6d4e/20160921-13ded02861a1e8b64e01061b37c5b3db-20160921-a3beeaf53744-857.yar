rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_a3beeaf53744_857 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"

  strings:
    $s1  = "n\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function" ascii
    $s2  = "ction f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){retur" ascii
    $s3  = "){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";}" ascii
    $s4  = "n \"MJq\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s5  = "return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s6  = "eturn \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})()" ascii
    $s7  = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(function f0" ascii
    $s8  = "(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){r" ascii
    $s9  = "function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){ret" ascii
    $s10 = "0(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";" ascii
    $s11 = "(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";" ascii
    $s12 = ",(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii
    $s13 = "(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s14 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DNa" ascii
    $s15 = "h\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functio" ascii
    $s16 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s17 = "){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s18 = "00(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd" ascii
    $s19 = "\"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s20 = "function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"OMd\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}