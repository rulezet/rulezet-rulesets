rule TTP_XOR_WriteProcessMemory_f654 {
  strings:
    $key_f654 = { a1 26 [2] 93 04 [2] 95 31 [2] bb 31 [2] 84 2d }

  condition:
    any of them
}