rule sig_20160330_4d6dc821fcef19bcbb0a4d944e9fa9a3 {
  meta:
    description = "datamaliciousorder - file 20160330_4d6dc821fcef19bcbb0a4d944e9fa9a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0184d7227523a48f295db4499547356684658e84431fa17cabae9d2b035b1e3e"

  strings:
    $s1 = "function PP4P(xx){;var C2mU=(4*\"dZa_CS.\\x8a\"[\"length\"]+4.0);O8_S=\"\";var DV8Z=String[\"fromCharCode\"]((0*\"VS-\\x87e3u7Jf" ascii
    $s2 = "function PP4P(xx){;var C2mU=(4*\"dZa_CS.\\x8a\"[\"length\"]+4.0);O8_S=\"\";var DV8Z=String[\"fromCharCode\"]((0*\"VS-\\x87e3u7Jf" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}