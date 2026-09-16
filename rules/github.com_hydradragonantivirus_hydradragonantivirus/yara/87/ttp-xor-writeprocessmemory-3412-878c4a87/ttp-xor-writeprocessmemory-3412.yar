rule TTP_XOR_WriteProcessMemory_3412 {
  strings:
    $key_3412 = { 63 60 [2] 51 42 [2] 57 77 [2] 79 77 [2] 46 6b }

  condition:
    any of them
}