rule TTP_XOR_WriteProcessMemory_a1db {
  strings:
    $key_a1db = { f6 a9 [2] c4 8b [2] c2 be [2] ec be [2] d3 a2 }

  condition:
    any of them
}