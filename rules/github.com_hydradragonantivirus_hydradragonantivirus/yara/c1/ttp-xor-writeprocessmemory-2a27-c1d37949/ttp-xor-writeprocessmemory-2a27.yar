rule TTP_XOR_WriteProcessMemory_2a27 {
  strings:
    $key_2a27 = { 7d 55 [2] 4f 77 [2] 49 42 [2] 67 42 [2] 58 5e }

  condition:
    any of them
}