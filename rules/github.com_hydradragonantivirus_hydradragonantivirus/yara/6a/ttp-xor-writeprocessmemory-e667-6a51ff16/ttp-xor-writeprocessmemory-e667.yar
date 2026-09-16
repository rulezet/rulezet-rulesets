rule TTP_XOR_WriteProcessMemory_e667 {
  strings:
    $key_e667 = { b1 15 [2] 83 37 [2] 85 02 [2] ab 02 [2] 94 1e }

  condition:
    any of them
}