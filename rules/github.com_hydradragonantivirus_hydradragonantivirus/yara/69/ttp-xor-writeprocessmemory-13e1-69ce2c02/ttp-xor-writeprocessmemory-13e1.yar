rule TTP_XOR_WriteProcessMemory_13e1 {
  strings:
    $key_13e1 = { 44 93 [2] 76 b1 [2] 70 84 [2] 5e 84 [2] 61 98 }

  condition:
    any of them
}