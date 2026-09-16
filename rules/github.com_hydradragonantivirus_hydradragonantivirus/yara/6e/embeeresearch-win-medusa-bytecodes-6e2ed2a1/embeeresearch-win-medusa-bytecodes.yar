rule EMBEERESEARCH_Win_Medusa_Bytecodes {
  meta:
    description = "Medusa Bytecodes"
    author      = "Matthew @ Embee_Research"
    id          = "48b659f8-cd26-540a-89b6-6349f8d21e8f"
    date        = "2023-08-27"
    modified    = "2024-03-03"
    reference   = "https://github.com/embee-research/Yara-detection-rules/"
    source_url  = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_medusa_dotnet_bytecodes.yar#L1-L17"
    license_url = "N/A"
    hash        = "a1211549b4e1a7befd953d03b4d929b3dc9f25ec6c1bc9c05ae92a0ec08fb77c"
    logic_hash  = "aa01afd6981af99625a9fca93e512cc00931aca18e55c5cb6dee11efb9ea2968"
    score       = 75
    quality     = 75
    tags        = ""

  strings:
    $s1 = { 1F ?? 8D ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 A2 25 17 72 ?? ?? ?? 70 28 ?? ?? ?? 0A A2 25 18 20 ?? ?? ?? 00 13 04 12 04 28 ?? ?? ?? 0A A2 25 19 20 ?? ?? ?? 00 13 ?? 12 }
    $s2 = "\\Medusa\\obj\\Release\\Medusa.pdb" ascii

  condition:
    $s1 or $s2
}