rule TTP_XOR_WriteProcessMemory_34f6 {
  strings:
    $key_34f6 = { 63 84 [2] 51 a6 [2] 57 93 [2] 79 93 [2] 46 8f }

  condition:
    any of them
}