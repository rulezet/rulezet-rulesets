rule Virus_Infector_Trojan_Agent_DVQW_3 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.Agent.DVQW_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a938e33feeed3a881be0d26dbe74911cbcde6331beb02b151c435a24cbf39384"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}