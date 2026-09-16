rule TTP_XOR_WriteProcessMemory_8e15 {
  strings:
    $key_8e15 = { d9 67 [2] eb 45 [2] ed 70 [2] c3 70 [2] fc 6c }

  condition:
    any of them
}