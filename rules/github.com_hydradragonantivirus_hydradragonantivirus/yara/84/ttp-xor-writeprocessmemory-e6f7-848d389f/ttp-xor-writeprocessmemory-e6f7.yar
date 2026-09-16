rule TTP_XOR_WriteProcessMemory_e6f7 {
  strings:
    $key_e6f7 = { b1 85 [2] 83 a7 [2] 85 92 [2] ab 92 [2] 94 8e }

  condition:
    any of them
}