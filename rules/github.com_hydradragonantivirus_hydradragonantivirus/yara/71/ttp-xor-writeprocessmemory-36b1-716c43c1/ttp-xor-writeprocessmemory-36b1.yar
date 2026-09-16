rule TTP_XOR_WriteProcessMemory_36b1 {
  strings:
    $key_36b1 = { 61 c3 [2] 53 e1 [2] 55 d4 [2] 7b d4 [2] 44 c8 }

  condition:
    any of them
}