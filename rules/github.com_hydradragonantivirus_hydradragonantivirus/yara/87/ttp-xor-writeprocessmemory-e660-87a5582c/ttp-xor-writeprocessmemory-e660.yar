rule TTP_XOR_WriteProcessMemory_e660 {
  strings:
    $key_e660 = { b1 12 [2] 83 30 [2] 85 05 [2] ab 05 [2] 94 19 }

  condition:
    any of them
}