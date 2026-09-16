rule TTP_XOR_WriteProcessMemory_1f26 {
  strings:
    $key_1f26 = { 48 54 [2] 7a 76 [2] 7c 43 [2] 52 43 [2] 6d 5f }

  condition:
    any of them
}