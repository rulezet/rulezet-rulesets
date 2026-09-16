rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_3567 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){r" ascii
    $s2 = "GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"SGs\";})(),(funct" ascii
    $s3 = "unction f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){re" ascii
    $s4 = ",(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s5 = "00(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq" ascii
    $s6 = " f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"T" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}