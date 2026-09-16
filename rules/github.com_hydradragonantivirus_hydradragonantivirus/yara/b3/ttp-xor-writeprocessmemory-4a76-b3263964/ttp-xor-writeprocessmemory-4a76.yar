rule TTP_XOR_WriteProcessMemory_4a76 {
  strings:
    $key_4a76 = { 1d 04 [2] 2f 26 [2] 29 13 [2] 07 13 [2] 38 0f }

  condition:
    any of them
}