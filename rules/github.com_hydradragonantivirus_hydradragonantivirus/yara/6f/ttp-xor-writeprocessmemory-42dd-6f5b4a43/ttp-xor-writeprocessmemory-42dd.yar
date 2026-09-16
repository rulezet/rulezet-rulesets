rule TTP_XOR_WriteProcessMemory_42dd {
  strings:
    $key_42dd = { 15 af [2] 27 8d [2] 21 b8 [2] 0f b8 [2] 30 a4 }

  condition:
    any of them
}