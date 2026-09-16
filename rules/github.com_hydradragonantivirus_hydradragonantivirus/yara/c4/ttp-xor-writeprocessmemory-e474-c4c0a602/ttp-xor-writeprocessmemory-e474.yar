rule TTP_XOR_WriteProcessMemory_e474 {
  strings:
    $key_e474 = { b3 06 [2] 81 24 [2] 87 11 [2] a9 11 [2] 96 0d }

  condition:
    any of them
}