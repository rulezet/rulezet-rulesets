rule TTP_XOR_WriteProcessMemory_2115 {
  strings:
    $key_2115 = { 76 67 [2] 44 45 [2] 42 70 [2] 6c 70 [2] 53 6c }

  condition:
    any of them
}