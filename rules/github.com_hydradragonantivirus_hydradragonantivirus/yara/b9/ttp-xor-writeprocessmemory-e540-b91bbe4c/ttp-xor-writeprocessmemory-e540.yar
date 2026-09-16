rule TTP_XOR_WriteProcessMemory_e540 {
  strings:
    $key_e540 = { b2 32 [2] 80 10 [2] 86 25 [2] a8 25 [2] 97 39 }

  condition:
    any of them
}