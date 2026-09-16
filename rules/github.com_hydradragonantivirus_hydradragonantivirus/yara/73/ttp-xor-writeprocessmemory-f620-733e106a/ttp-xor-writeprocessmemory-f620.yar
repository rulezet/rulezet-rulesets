rule TTP_XOR_WriteProcessMemory_f620 {
  strings:
    $key_f620 = { a1 52 [2] 93 70 [2] 95 45 [2] bb 45 [2] 84 59 }

  condition:
    any of them
}