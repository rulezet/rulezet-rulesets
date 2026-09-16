rule _20160921_6ad2178e7d047e60c71f9fe1ca457b74_20160921_7f829eb25609_5354 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash3       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash4       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"

  strings:
    $s1 = ";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f00" ascii
    $s2 = " f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy" ascii
    $s3 = "turn \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s4 = "(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii
    $s5 = ";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}