rule TTP_XOR_WriteProcessMemory_4176 {
  strings:
    $key_4176 = { 16 04 [2] 24 26 [2] 22 13 [2] 0c 13 [2] 33 0f }

  condition:
    any of them
}