rule TTP_XOR_WriteProcessMemory_7f27 {
  strings:
    $key_7f27 = { 28 55 [2] 1a 77 [2] 1c 42 [2] 32 42 [2] 0d 5e }

  condition:
    any of them
}