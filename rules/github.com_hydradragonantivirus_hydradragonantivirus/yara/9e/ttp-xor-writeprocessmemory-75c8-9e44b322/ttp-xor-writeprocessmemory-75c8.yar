rule TTP_XOR_WriteProcessMemory_75c8 {
  strings:
    $key_75c8 = { 22 ba [2] 10 98 [2] 16 ad [2] 38 ad [2] 07 b1 }

  condition:
    any of them
}