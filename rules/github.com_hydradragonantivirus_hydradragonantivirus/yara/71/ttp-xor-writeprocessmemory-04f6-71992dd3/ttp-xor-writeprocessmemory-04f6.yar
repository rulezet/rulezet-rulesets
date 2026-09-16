rule TTP_XOR_WriteProcessMemory_04f6 {
  strings:
    $key_04f6 = { 53 84 [2] 61 a6 [2] 67 93 [2] 49 93 [2] 76 8f }

  condition:
    any of them
}