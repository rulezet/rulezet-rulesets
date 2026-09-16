rule TTP_XOR_WriteProcessMemory_2e12 {
  strings:
    $key_2e12 = { 79 60 [2] 4b 42 [2] 4d 77 [2] 63 77 [2] 5c 6b }

  condition:
    any of them
}