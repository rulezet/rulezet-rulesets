rule TTP_XOR_WriteProcessMemory_2e76 {
  strings:
    $key_2e76 = { 79 04 [2] 4b 26 [2] 4d 13 [2] 63 13 [2] 5c 0f }

  condition:
    any of them
}