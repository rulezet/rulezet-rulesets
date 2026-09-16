rule TTP_XOR_WriteProcessMemory_2f26 {
  strings:
    $key_2f26 = { 78 54 [2] 4a 76 [2] 4c 43 [2] 62 43 [2] 5d 5f }

  condition:
    any of them
}