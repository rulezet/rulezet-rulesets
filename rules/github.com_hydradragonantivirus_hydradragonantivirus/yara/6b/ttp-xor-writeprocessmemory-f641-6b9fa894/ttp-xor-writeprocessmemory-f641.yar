rule TTP_XOR_WriteProcessMemory_f641 {
  strings:
    $key_f641 = { a1 33 [2] 93 11 [2] 95 24 [2] bb 24 [2] 84 38 }

  condition:
    any of them
}