rule TTP_XOR_WriteProcessMemory_3f76 {
  strings:
    $key_3f76 = { 68 04 [2] 5a 26 [2] 5c 13 [2] 72 13 [2] 4d 0f }

  condition:
    any of them
}