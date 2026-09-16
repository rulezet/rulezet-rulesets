rule TTP_XOR_WriteProcessMemory_84db {
  strings:
    $key_84db = { d3 a9 [2] e1 8b [2] e7 be [2] c9 be [2] f6 a2 }

  condition:
    any of them
}