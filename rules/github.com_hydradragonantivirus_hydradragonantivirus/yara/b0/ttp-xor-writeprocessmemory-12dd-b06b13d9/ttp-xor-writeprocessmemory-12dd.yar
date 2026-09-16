rule TTP_XOR_WriteProcessMemory_12dd {
  strings:
    $key_12dd = { 45 af [2] 77 8d [2] 71 b8 [2] 5f b8 [2] 60 a4 }

  condition:
    any of them
}