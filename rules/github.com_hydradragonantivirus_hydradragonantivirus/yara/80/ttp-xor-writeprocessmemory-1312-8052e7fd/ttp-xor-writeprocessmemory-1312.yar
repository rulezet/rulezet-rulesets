rule TTP_XOR_WriteProcessMemory_1312 {
  strings:
    $key_1312 = { 44 60 [2] 76 42 [2] 70 77 [2] 5e 77 [2] 61 6b }

  condition:
    any of them
}