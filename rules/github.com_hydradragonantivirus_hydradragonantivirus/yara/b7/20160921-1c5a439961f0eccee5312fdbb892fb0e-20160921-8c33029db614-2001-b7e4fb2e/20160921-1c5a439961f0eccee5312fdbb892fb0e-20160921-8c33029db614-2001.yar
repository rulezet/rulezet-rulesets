rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_8c33029db614_2001 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_8c33029db61426a234eddfae1623641b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"

  strings:
    $s1 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTi\";})()" ascii
    $s2 = "return \"HJm\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s4 = "\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s5 = "000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn" ascii
    $s6 = "\"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s7 = "function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RLk\";})(),(function f000(){re" ascii
    $s8 = "tion f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return" ascii
    $s9 = "n \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}