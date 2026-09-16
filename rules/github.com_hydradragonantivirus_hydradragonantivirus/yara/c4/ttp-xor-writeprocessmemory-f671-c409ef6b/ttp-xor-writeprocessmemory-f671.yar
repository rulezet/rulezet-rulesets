rule TTP_XOR_WriteProcessMemory_f671 {
  strings:
    $key_f671 = { a1 03 [2] 93 21 [2] 95 14 [2] bb 14 [2] 84 08 }

  condition:
    any of them
}