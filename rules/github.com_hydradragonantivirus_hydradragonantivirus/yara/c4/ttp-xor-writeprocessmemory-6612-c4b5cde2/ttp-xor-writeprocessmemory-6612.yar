rule TTP_XOR_WriteProcessMemory_6612 {
  strings:
    $key_6612 = { 31 60 [2] 03 42 [2] 05 77 [2] 2b 77 [2] 14 6b }

  condition:
    any of them
}