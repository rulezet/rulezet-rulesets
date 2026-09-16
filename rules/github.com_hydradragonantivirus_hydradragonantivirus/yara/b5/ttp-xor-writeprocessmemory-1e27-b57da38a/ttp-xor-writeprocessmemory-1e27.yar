rule TTP_XOR_WriteProcessMemory_1e27 {
  strings:
    $key_1e27 = { 49 55 [2] 7b 77 [2] 7d 42 [2] 53 42 [2] 6c 5e }

  condition:
    any of them
}