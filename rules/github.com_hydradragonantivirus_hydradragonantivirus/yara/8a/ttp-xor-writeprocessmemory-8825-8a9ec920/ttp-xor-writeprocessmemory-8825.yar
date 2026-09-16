rule TTP_XOR_WriteProcessMemory_8825 {
  strings:
    $key_8825 = { df 57 [2] ed 75 [2] eb 40 [2] c5 40 [2] fa 5c }

  condition:
    any of them
}