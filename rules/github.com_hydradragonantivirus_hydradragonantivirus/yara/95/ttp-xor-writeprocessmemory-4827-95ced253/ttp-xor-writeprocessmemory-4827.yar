rule TTP_XOR_WriteProcessMemory_4827 {
  strings:
    $key_4827 = { 1f 55 [2] 2d 77 [2] 2b 42 [2] 05 42 [2] 3a 5e }

  condition:
    any of them
}