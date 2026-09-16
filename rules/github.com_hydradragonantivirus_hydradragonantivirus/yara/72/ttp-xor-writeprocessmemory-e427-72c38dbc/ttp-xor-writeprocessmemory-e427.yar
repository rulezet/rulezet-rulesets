rule TTP_XOR_WriteProcessMemory_e427 {
  strings:
    $key_e427 = { b3 55 [2] 81 77 [2] 87 42 [2] a9 42 [2] 96 5e }

  condition:
    any of them
}