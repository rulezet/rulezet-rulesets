rule TTP_XOR_WriteProcessMemory_0136 {
  strings:
    $key_0136 = { 56 44 [2] 64 66 [2] 62 53 [2] 4c 53 [2] 73 4f }

  condition:
    any of them
}