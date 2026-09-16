rule TTP_XOR_WriteProcessMemory_8805 {
  strings:
    $key_8805 = { df 77 [2] ed 55 [2] eb 60 [2] c5 60 [2] fa 7c }

  condition:
    any of them
}