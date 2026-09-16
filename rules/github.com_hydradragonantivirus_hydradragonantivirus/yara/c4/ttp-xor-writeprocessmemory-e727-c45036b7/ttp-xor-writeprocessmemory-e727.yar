rule TTP_XOR_WriteProcessMemory_e727 {
  strings:
    $key_e727 = { b0 55 [2] 82 77 [2] 84 42 [2] aa 42 [2] 95 5e }

  condition:
    any of them
}