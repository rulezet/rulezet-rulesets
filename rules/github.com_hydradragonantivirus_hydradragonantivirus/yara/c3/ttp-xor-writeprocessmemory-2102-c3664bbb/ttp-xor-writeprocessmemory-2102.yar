rule TTP_XOR_WriteProcessMemory_2102 {
  strings:
    $key_2102 = { 76 70 [2] 44 52 [2] 42 67 [2] 6c 67 [2] 53 7b }

  condition:
    any of them
}