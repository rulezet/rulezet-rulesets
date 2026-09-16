rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_85f6e34eb7e2_3463 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"

  strings:
    $s1 = "tion f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){retur" ascii
    $s2 = "ction f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})()" ascii
    $s4 = "n f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii
    $s5 = "){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";" ascii
    $s6 = "{return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}