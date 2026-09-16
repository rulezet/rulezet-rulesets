rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_319493db332e_4516 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash3       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash4       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash5       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash6       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "ion f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s2 = "nction f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){retu" ascii
    $s3 = "000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs" ascii
    $s4 = "urn \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(fu" ascii
    $s5 = "BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}