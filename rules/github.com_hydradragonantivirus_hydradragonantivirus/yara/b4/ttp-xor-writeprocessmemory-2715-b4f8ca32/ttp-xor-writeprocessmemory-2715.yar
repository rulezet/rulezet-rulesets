rule TTP_XOR_WriteProcessMemory_2715 {
  strings:
    $key_2715 = { 70 67 [2] 42 45 [2] 44 70 [2] 6a 70 [2] 55 6c }

  condition:
    any of them
}