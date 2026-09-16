rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_d74d6a32efd0_4247 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = "n \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s2 = ";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s3 = "tion f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s4 = "on f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"" ascii
    $s5 = "000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}