rule TTP_XOR_WriteProcessMemory_5612 {
  strings:
    $key_5612 = { 01 60 [2] 33 42 [2] 35 77 [2] 1b 77 [2] 24 6b }

  condition:
    any of them
}