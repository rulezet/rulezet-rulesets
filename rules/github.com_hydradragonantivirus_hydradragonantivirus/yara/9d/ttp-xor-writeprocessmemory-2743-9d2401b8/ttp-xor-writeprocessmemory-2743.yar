rule TTP_XOR_WriteProcessMemory_2743 {
  strings:
    $key_2743 = { 70 31 [2] 42 13 [2] 44 26 [2] 6a 26 [2] 55 3a }

  condition:
    any of them
}