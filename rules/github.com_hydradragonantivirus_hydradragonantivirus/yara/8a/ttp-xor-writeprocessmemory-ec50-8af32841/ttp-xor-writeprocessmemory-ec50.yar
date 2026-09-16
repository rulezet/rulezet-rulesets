rule TTP_XOR_WriteProcessMemory_ec50 {
  strings:
    $key_ec50 = { bb 22 [2] 89 00 [2] 8f 35 [2] a1 35 [2] 9e 29 }

  condition:
    any of them
}