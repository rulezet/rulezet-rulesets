rule TTP_XOR_WriteProcessMemory_2112 {
  strings:
    $key_2112 = { 76 60 [2] 44 42 [2] 42 77 [2] 6c 77 [2] 53 6b }

  condition:
    any of them
}