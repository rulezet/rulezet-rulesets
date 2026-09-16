rule TTP_XOR_WriteProcessMemory_6db9 {
  strings:
    $key_6db9 = { 3a cb [2] 08 e9 [2] 0e dc [2] 20 dc [2] 1f c0 }

  condition:
    any of them
}