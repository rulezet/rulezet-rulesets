rule TTP_XOR_WriteProcessMemory_8827 {
  strings:
    $key_8827 = { df 55 [2] ed 77 [2] eb 42 [2] c5 42 [2] fa 5e }

  condition:
    any of them
}