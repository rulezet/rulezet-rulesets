rule TTP_XOR_WriteProcessMemory_88e5 {
  strings:
    $key_88e5 = { df 97 [2] ed b5 [2] eb 80 [2] c5 80 [2] fa 9c }

  condition:
    any of them
}