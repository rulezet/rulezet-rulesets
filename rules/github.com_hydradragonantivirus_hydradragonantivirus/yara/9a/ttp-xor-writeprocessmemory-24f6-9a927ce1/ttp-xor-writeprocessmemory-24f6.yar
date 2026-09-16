rule TTP_XOR_WriteProcessMemory_24f6 {
  strings:
    $key_24f6 = { 73 84 [2] 41 a6 [2] 47 93 [2] 69 93 [2] 56 8f }

  condition:
    any of them
}