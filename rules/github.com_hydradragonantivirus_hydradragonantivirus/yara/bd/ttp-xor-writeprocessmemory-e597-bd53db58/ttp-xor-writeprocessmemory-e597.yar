rule TTP_XOR_WriteProcessMemory_e597 {
  strings:
    $key_e597 = { b2 e5 [2] 80 c7 [2] 86 f2 [2] a8 f2 [2] 97 ee }

  condition:
    any of them
}