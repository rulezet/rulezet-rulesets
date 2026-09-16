rule Virus_Hijack_Trojan_Downloader_JUKO_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Downloader.JUKO_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a2882c35e50637024281ca17a1b28177a809b01b4503d169b140fc58393a2b9"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}