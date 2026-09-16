rule TTP_XOR_WriteProcessMemory_e604 {
  strings:
    $key_e604 = { b1 76 [2] 83 54 [2] 85 61 [2] ab 61 [2] 94 7d }

  condition:
    any of them
}