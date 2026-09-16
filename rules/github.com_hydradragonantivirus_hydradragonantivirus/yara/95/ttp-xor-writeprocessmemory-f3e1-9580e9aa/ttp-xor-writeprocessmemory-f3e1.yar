rule TTP_XOR_WriteProcessMemory_f3e1 {
  strings:
    $key_f3e1 = { a4 93 [2] 96 b1 [2] 90 84 [2] be 84 [2] 81 98 }

  condition:
    any of them
}