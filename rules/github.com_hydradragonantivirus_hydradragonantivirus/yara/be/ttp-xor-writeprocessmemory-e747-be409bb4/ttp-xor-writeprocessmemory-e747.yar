rule TTP_XOR_WriteProcessMemory_e747 {
  strings:
    $key_e747 = { b0 35 [2] 82 17 [2] 84 22 [2] aa 22 [2] 95 3e }

  condition:
    any of them
}