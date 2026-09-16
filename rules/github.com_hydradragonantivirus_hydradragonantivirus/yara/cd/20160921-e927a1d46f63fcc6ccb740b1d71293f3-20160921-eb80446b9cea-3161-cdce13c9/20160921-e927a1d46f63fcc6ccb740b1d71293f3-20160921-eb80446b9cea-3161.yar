rule _20160921_e927a1d46f63fcc6ccb740b1d71293f3_20160921_eb80446b9cea_3161 {
  meta:
    description = "datamaliciousorder - from files 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"
    hash2       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"

  strings:
    $s1 = " f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um" ascii
    $s2 = "eturn \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s3 = "00(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa" ascii
    $s4 = "urn \"KZr\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"KZr\";})()," ascii
    $s5 = "Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(functio" ascii
    $s6 = "(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(" ascii
    $s7 = "f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}