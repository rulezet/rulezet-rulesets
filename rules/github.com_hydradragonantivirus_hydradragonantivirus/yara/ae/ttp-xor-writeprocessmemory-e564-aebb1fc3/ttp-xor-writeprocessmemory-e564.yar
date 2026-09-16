rule TTP_XOR_WriteProcessMemory_e564 {
  strings:
    $key_e564 = { b2 16 [2] 80 34 [2] 86 01 [2] a8 01 [2] 97 1d }

  condition:
    any of them
}