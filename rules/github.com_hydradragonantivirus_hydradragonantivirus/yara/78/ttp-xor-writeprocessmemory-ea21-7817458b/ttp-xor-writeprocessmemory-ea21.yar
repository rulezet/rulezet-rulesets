rule TTP_XOR_WriteProcessMemory_ea21 {
  strings:
    $key_ea21 = { bd 53 [2] 8f 71 [2] 89 44 [2] a7 44 [2] 98 58 }

  condition:
    any of them
}