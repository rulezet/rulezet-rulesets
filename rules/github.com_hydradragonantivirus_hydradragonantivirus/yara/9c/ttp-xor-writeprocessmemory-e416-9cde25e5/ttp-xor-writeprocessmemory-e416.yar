rule TTP_XOR_WriteProcessMemory_e416 {
  strings:
    $key_e416 = { b3 64 [2] 81 46 [2] 87 73 [2] a9 73 [2] 96 6f }

  condition:
    any of them
}