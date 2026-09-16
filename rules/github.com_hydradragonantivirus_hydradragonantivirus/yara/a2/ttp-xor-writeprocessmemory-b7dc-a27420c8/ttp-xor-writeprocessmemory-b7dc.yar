rule TTP_XOR_WriteProcessMemory_b7dc {
  strings:
    $key_b7dc = { e0 ae [2] d2 8c [2] d4 b9 [2] fa b9 [2] c5 a5 }

  condition:
    any of them
}