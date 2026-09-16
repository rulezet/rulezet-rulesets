rule TTP_XOR_WriteProcessMemory_2733 {
  strings:
    $key_2733 = { 70 41 [2] 42 63 [2] 44 56 [2] 6a 56 [2] 55 4a }

  condition:
    any of them
}