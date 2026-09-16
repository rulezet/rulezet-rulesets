rule _20160921_e927a1d46f63fcc6ccb740b1d71293f3_20160921_eba3e9dc8ad6_4077 {
  meta:
    description = "datamaliciousorder - from files 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "n f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YT" ascii
    $s2 = "\"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){retur" ascii
    $s4 = "ction f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return" ascii
    $s5 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f00" ascii
    $s6 = "turn \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}