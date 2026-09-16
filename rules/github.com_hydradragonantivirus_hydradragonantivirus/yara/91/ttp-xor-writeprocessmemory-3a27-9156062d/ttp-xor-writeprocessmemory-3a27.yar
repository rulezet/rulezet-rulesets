rule TTP_XOR_WriteProcessMemory_3a27 {
  strings:
    $key_3a27 = { 6d 55 [2] 5f 77 [2] 59 42 [2] 77 42 [2] 48 5e }

  condition:
    any of them
}