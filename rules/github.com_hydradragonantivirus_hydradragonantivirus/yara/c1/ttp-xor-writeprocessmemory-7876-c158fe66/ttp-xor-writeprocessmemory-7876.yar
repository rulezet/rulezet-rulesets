rule TTP_XOR_WriteProcessMemory_7876 {
  strings:
    $key_7876 = { 2f 04 [2] 1d 26 [2] 1b 13 [2] 35 13 [2] 0a 0f }

  condition:
    any of them
}