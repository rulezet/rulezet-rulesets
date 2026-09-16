rule TTP_XOR_WriteProcessMemory_e556 {
  strings:
    $key_e556 = { b2 24 [2] 80 06 [2] 86 33 [2] a8 33 [2] 97 2f }

  condition:
    any of them
}