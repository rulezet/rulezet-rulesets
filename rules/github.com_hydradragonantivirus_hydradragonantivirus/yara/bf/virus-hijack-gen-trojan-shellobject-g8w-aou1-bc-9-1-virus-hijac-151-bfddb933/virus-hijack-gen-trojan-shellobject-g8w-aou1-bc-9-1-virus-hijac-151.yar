import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_9_1_Virus_Hijac_151 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aq1NpPf_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "addc34ec88fdb874a1b821f4f8062d41978d98081f2eb5e93a86d3205842e4b1"
    hash2       = "5b23680d97df8ba6bb12f3bdd28a1779ea2ec740b3c5ab8e3ba6774a7b5a557f"

  strings:
    $s1  = "|------- Phoenix Keylogger - Passwords -------|" fullword wide
    $s2  = "|------- Phoenix Keylogger - Clipboard -------|" fullword wide
    $s3  = "|------- Phoenix Keylogger - Logs -------|" fullword wide
    $s4  = "Opera Password" fullword wide
    $s5  = "Postbox Password" fullword wide
    $s6  = "Password: {0}" fullword wide
    $s7  = "Comodo Password" fullword wide
    $s8  = "SeaMonkey Password" fullword wide
    $s9  = "CoC CoC Password" fullword wide
    $s10 = "Liebao Password" fullword wide
    $s11 = "360 Password" fullword wide
    $s12 = "QQ Password" fullword wide
    $s13 = "Vivaldi Password" fullword wide
    $s14 = "Brave Password" fullword wide
    $s15 = "Blisk Password" fullword wide
    $s16 = "Avast Password" fullword wide
    $s17 = "SRware Iron Password" fullword wide
    $s18 = "Torch Password" fullword wide
    $s19 = "Orbitum Password" fullword wide
    $s20 = "UC Password" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}