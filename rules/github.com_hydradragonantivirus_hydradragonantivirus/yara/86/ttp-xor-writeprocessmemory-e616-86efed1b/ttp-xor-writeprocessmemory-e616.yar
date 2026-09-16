rule TTP_XOR_WriteProcessMemory_e616 {
  strings:
    $key_e616 = { b1 64 [2] 83 46 [2] 85 73 [2] ab 73 [2] 94 6f }

  condition:
    any of them
}