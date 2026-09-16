rule TTP_XOR_WriteProcessMemory_8875 {
  strings:
    $key_8875 = { df 07 [2] ed 25 [2] eb 10 [2] c5 10 [2] fa 0c }

  condition:
    any of them
}