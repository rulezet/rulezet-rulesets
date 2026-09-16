rule TTP_XOR_WriteProcessMemory_5c76 {
  strings:
    $key_5c76 = { 0b 04 [2] 39 26 [2] 3f 13 [2] 11 13 [2] 2e 0f }

  condition:
    any of them
}