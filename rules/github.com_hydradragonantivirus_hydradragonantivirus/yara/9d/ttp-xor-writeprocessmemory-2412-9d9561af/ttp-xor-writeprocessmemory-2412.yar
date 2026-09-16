rule TTP_XOR_WriteProcessMemory_2412 {
  strings:
    $key_2412 = { 73 60 [2] 41 42 [2] 47 77 [2] 69 77 [2] 56 6b }

  condition:
    any of them
}