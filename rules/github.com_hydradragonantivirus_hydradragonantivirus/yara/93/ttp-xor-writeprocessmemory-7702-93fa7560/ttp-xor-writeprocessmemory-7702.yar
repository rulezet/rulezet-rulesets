rule TTP_XOR_WriteProcessMemory_7702 {
  strings:
    $key_7702 = { 20 70 [2] 12 52 [2] 14 67 [2] 3a 67 [2] 05 7b }

  condition:
    any of them
}