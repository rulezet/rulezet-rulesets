rule TTP_XOR_WriteProcessMemory_4ad4 {
  strings:
    $key_4ad4 = { 1d a6 [2] 2f 84 [2] 29 b1 [2] 07 b1 [2] 38 ad }

  condition:
    any of them
}