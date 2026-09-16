rule TTP_XOR_WriteProcessMemory_50c8 {
  strings:
    $key_50c8 = { 07 ba [2] 35 98 [2] 33 ad [2] 1d ad [2] 22 b1 }

  condition:
    any of them
}