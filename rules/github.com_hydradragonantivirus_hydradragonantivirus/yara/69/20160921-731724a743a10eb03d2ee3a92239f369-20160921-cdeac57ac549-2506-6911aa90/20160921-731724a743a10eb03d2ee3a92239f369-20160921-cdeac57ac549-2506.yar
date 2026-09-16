rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_cdeac57ac549_2506 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1 = " \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(funct" ascii
    $s2 = "ction f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){retur" ascii
    $s3 = "rn \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = "(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";}" ascii
    $s5 = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function " ascii
    $s6 = " f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TR" ascii
    $s7 = "ion f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s8 = ",(function f000(){return \"WIj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}