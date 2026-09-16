rule TTP_XOR_WriteProcessMemory_6827 {
  strings:
    $key_6827 = { 3f 55 [2] 0d 77 [2] 0b 42 [2] 25 42 [2] 1a 5e }

  condition:
    any of them
}