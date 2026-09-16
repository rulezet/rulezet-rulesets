rule TTP_XOR_WriteProcessMemory_caf6 {
  strings:
    $key_caf6 = { 9d 84 [2] af a6 [2] a9 93 [2] 87 93 [2] b8 8f }

  condition:
    any of them
}