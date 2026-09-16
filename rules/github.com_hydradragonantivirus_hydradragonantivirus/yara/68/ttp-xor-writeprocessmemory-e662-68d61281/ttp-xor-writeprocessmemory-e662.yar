rule TTP_XOR_WriteProcessMemory_e662 {
  strings:
    $key_e662 = { b1 10 [2] 83 32 [2] 85 07 [2] ab 07 [2] 94 1b }

  condition:
    any of them
}