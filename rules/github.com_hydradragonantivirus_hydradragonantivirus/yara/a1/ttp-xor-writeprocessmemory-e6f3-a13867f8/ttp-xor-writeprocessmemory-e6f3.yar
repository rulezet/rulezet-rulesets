rule TTP_XOR_WriteProcessMemory_e6f3 {
  strings:
    $key_e6f3 = { b1 81 [2] 83 a3 [2] 85 96 [2] ab 96 [2] 94 8a }

  condition:
    any of them
}