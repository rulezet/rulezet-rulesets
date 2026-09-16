rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_111_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cb500728c7c6d8d3f3a568beb6c138381e39c34601193f9be752eb3b60e9be2"

  strings:
    $s1 = "http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.jq\\" fullword ascii
    $s2 = "agree to terminate that su" fullword ascii
    $s3 = "How can I use the software? The software is licensed, not sold. Under this agreement we grant youkp(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}