rule TTP_XOR_WriteProcessMemory_a6db {
  strings:
    $key_a6db = { f1 a9 [2] c3 8b [2] c5 be [2] eb be [2] d4 a2 }

  condition:
    any of them
}