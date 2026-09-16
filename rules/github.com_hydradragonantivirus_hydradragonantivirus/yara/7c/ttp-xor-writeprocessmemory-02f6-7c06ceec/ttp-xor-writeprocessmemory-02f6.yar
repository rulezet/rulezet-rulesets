rule TTP_XOR_WriteProcessMemory_02f6 {
  strings:
    $key_02f6 = { 55 84 [2] 67 a6 [2] 61 93 [2] 4f 93 [2] 70 8f }

  condition:
    any of them
}