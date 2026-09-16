rule TTP_XOR_WriteProcessMemory_e6e2 {
  strings:
    $key_e6e2 = { b1 90 [2] 83 b2 [2] 85 87 [2] ab 87 [2] 94 9b }

  condition:
    any of them
}