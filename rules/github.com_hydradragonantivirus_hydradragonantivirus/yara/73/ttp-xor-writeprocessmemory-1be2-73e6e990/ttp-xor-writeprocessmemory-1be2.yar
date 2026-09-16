rule TTP_XOR_WriteProcessMemory_1be2 {
  strings:
    $key_1be2 = { 4c 90 [2] 7e b2 [2] 78 87 [2] 56 87 [2] 69 9b }

  condition:
    any of them
}