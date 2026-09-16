rule TTP_XOR_WriteProcessMemory_5a27 {
  strings:
    $key_5a27 = { 0d 55 [2] 3f 77 [2] 39 42 [2] 17 42 [2] 28 5e }

  condition:
    any of them
}