rule TTP_XOR_WriteProcessMemory_b6db {
  strings:
    $key_b6db = { e1 a9 [2] d3 8b [2] d5 be [2] fb be [2] c4 a2 }

  condition:
    any of them
}