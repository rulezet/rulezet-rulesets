rule TTP_XOR_WriteProcessMemory_4273 {
  strings:
    $key_4273 = { 15 01 [2] 27 23 [2] 21 16 [2] 0f 16 [2] 30 0a }

  condition:
    any of them
}