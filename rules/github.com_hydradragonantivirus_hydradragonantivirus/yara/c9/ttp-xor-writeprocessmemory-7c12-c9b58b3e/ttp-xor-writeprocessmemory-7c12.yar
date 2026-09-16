rule TTP_XOR_WriteProcessMemory_7c12 {
  strings:
    $key_7c12 = { 2b 60 [2] 19 42 [2] 1f 77 [2] 31 77 [2] 0e 6b }

  condition:
    any of them
}