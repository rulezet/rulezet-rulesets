rule TTP_XOR_WriteProcessMemory_3476 {
  strings:
    $key_3476 = { 63 04 [2] 51 26 [2] 57 13 [2] 79 13 [2] 46 0f }

  condition:
    any of them
}