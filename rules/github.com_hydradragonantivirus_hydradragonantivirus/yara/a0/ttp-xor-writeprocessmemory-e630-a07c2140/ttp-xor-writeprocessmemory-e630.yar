rule TTP_XOR_WriteProcessMemory_e630 {
  strings:
    $key_e630 = { b1 42 [2] 83 60 [2] 85 55 [2] ab 55 [2] 94 49 }

  condition:
    any of them
}