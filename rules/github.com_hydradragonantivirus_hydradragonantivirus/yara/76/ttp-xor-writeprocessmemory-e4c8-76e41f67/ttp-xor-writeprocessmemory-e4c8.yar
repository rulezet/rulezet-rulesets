rule TTP_XOR_WriteProcessMemory_e4c8 {
  strings:
    $key_e4c8 = { b3 ba [2] 81 98 [2] 87 ad [2] a9 ad [2] 96 b1 }

  condition:
    any of them
}