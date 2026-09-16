rule TTP_XOR_WriteProcessMemory_ece4 {
  strings:
    $key_ece4 = { bb 96 [2] 89 b4 [2] 8f 81 [2] a1 81 [2] 9e 9d }

  condition:
    any of them
}