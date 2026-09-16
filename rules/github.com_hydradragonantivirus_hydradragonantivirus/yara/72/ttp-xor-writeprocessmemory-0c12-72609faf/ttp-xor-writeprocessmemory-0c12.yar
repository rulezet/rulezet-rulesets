rule TTP_XOR_WriteProcessMemory_0c12 {
  strings:
    $key_0c12 = { 5b 60 [2] 69 42 [2] 6f 77 [2] 41 77 [2] 7e 6b }

  condition:
    any of them
}