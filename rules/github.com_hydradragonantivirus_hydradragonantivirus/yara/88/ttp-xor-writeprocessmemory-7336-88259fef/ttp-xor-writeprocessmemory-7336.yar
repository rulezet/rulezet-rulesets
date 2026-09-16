rule TTP_XOR_WriteProcessMemory_7336 {
  strings:
    $key_7336 = { 24 44 [2] 16 66 [2] 10 53 [2] 3e 53 [2] 01 4f }

  condition:
    any of them
}