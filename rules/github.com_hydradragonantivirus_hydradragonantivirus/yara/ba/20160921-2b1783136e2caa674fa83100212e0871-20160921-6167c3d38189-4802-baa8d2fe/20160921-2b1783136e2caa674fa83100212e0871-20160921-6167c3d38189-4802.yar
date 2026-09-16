rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_4802 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash4       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "0(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";}" ascii
    $s2 = "000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s3 = "return \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})" ascii
    $s4 = "n \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s5 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}