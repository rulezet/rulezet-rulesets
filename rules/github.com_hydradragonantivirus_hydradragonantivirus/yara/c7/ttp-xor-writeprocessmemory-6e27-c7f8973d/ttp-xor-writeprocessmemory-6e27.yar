rule TTP_XOR_WriteProcessMemory_6e27 {
  strings:
    $key_6e27 = { 39 55 [2] 0b 77 [2] 0d 42 [2] 23 42 [2] 1c 5e }

  condition:
    any of them
}