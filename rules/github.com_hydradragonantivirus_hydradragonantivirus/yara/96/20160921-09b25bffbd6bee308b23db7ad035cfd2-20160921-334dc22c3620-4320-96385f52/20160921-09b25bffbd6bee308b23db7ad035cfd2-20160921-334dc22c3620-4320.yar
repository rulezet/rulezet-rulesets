rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_334dc22c3620_4320 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash3       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "unction f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){ret" ascii
    $s2 = "(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";}" ascii
    $s3 = "(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){re" ascii
    $s4 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}