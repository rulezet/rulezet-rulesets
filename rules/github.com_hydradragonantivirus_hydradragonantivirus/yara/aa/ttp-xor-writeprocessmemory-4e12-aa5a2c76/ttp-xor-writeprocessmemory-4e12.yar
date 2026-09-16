rule TTP_XOR_WriteProcessMemory_4e12 {
  strings:
    $key_4e12 = { 19 60 [2] 2b 42 [2] 2d 77 [2] 03 77 [2] 3c 6b }

  condition:
    any of them
}