rule TTP_XOR_WriteProcessMemory_6736 {
  strings:
    $key_6736 = { 30 44 [2] 02 66 [2] 04 53 [2] 2a 53 [2] 15 4f }

  condition:
    any of them
}