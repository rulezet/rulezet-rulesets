rule TTP_XOR_WriteProcessMemory_38f6 {
  strings:
    $key_38f6 = { 6f 84 [2] 5d a6 [2] 5b 93 [2] 75 93 [2] 4a 8f }

  condition:
    any of them
}