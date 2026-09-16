rule TTP_XOR_WriteProcessMemory_7e12 {
  strings:
    $key_7e12 = { 29 60 [2] 1b 42 [2] 1d 77 [2] 33 77 [2] 0c 6b }

  condition:
    any of them
}