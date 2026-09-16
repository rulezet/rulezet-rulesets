rule TTP_XOR_WriteProcessMemory_f670 {
  strings:
    $key_f670 = { a1 02 [2] 93 20 [2] 95 15 [2] bb 15 [2] 84 09 }

  condition:
    any of them
}