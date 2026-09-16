rule _20160921_336aeb1d023bcb845a70471edfe8a8f9_20160921_65ff2a70ce98_2866 {
  meta:
    description = "datamaliciousorder - from files 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash2       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(" ascii
    $s2 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s3 = "t\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s4 = "rn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Av\";})(),(f" ascii
    $s5 = "uck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\"" ascii
    $s6 = ")(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuc" ascii
    $s7 = "nction fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}