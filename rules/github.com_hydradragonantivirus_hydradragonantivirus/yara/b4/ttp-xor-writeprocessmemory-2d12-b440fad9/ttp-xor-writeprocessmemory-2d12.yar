rule TTP_XOR_WriteProcessMemory_2d12 {
  strings:
    $key_2d12 = { 7a 60 [2] 48 42 [2] 4e 77 [2] 60 77 [2] 5f 6b }

  condition:
    any of them
}