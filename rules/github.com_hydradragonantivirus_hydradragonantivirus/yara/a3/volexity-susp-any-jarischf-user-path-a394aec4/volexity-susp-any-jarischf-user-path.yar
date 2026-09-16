rule VOLEXITY_Susp_Any_Jarischf_User_Path: FILE MEMORY {
  meta:
    description  = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
    author       = "threatintel@volexity.com"
    id           = "062a6fdb-c516-5643-9c7c-deff32eeb95e"
    date         = "2024-04-10"
    modified     = "2024-04-12"
    reference    = "TIB-20240412"
    source_url   = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L57-L78"
    license_url  = "https://github.com/volexity/threat-intel/blob/62e031ea574efde68dac7d38dc23438466a5302b/LICENSE.txt"
    logic_hash   = "574d5b1fadb91c39251600e7d73d4993d4b16565bd1427a0e8d6ed4e7905ab54"
    score        = 50
    quality      = 80
    tags         = "FILE, MEMORY"
    hash1        = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
    os           = "all"
    os_arch      = "all"
    scan_context = "file,memory"
    license      = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id      = 10424
    version      = 4

  strings:
    $proj_1 = "/home/jarischf/"

  condition:
    any of ($proj_*)
}