rule TTP_XOR_WriteProcessMemory_7e76 {
  strings:
    $key_7e76 = { 29 04 [2] 1b 26 [2] 1d 13 [2] 33 13 [2] 0c 0f }

  condition:
    any of them
}