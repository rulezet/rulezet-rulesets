rule TTP_XOR_WriteProcessMemory_22e1 {
  strings:
    $key_22e1 = { 75 93 [2] 47 b1 [2] 41 84 [2] 6f 84 [2] 50 98 }

  condition:
    any of them
}