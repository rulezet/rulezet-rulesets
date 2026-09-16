rule TTP_XOR_WriteProcessMemory_2767 {
  strings:
    $key_2767 = { 70 15 [2] 42 37 [2] 44 02 [2] 6a 02 [2] 55 1e }

  condition:
    any of them
}