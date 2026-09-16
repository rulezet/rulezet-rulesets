rule TTP_XOR_WriteProcessMemory_2702 {
  strings:
    $key_2702 = { 70 70 [2] 42 52 [2] 44 67 [2] 6a 67 [2] 55 7b }

  condition:
    any of them
}