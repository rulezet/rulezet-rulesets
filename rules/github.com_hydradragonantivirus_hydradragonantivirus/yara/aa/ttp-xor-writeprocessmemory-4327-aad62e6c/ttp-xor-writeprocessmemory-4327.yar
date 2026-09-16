rule TTP_XOR_WriteProcessMemory_4327 {
  strings:
    $key_4327 = { 14 55 [2] 26 77 [2] 20 42 [2] 0e 42 [2] 31 5e }

  condition:
    any of them
}