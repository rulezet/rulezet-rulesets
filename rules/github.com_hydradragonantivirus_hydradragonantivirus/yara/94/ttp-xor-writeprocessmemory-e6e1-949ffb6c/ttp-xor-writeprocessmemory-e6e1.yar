rule TTP_XOR_WriteProcessMemory_e6e1 {
  strings:
    $key_e6e1 = { b1 93 [2] 83 b1 [2] 85 84 [2] ab 84 [2] 94 98 }

  condition:
    any of them
}