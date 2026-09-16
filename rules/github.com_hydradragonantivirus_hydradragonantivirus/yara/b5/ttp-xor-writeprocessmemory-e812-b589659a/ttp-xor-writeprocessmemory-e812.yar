rule TTP_XOR_WriteProcessMemory_e812 {
  strings:
    $key_e812 = { bf 60 [2] 8d 42 [2] 8b 77 [2] a5 77 [2] 9a 6b }

  condition:
    any of them
}