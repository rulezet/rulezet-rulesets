rule TTP_XOR_WriteProcessMemory_54f6 {
  strings:
    $key_54f6 = { 03 84 [2] 31 a6 [2] 37 93 [2] 19 93 [2] 26 8f }

  condition:
    any of them
}