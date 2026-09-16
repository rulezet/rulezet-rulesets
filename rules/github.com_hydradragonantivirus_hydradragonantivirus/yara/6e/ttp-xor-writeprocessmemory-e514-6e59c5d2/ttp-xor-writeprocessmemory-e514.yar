rule TTP_XOR_WriteProcessMemory_e514 {
  strings:
    $key_e514 = { b2 66 [2] 80 44 [2] 86 71 [2] a8 71 [2] 97 6d }

  condition:
    any of them
}