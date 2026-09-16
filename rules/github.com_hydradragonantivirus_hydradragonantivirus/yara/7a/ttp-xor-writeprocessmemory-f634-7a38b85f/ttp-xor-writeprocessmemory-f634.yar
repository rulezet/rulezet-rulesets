rule TTP_XOR_WriteProcessMemory_f634 {
  strings:
    $key_f634 = { a1 46 [2] 93 64 [2] 95 51 [2] bb 51 [2] 84 4d }

  condition:
    any of them
}