rule TTP_XOR_WriteProcessMemory_e622 {
  strings:
    $key_e622 = { b1 50 [2] 83 72 [2] 85 47 [2] ab 47 [2] 94 5b }

  condition:
    any of them
}