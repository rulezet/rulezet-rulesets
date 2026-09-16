rule TTP_XOR_WriteProcessMemory_6b76 {
  strings:
    $key_6b76 = { 3c 04 [2] 0e 26 [2] 08 13 [2] 26 13 [2] 19 0f }

  condition:
    any of them
}