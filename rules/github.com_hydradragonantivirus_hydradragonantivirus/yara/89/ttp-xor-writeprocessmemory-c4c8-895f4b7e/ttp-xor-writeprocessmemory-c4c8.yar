rule TTP_XOR_WriteProcessMemory_c4c8 {
  strings:
    $key_c4c8 = { 93 ba [2] a1 98 [2] a7 ad [2] 89 ad [2] b6 b1 }

  condition:
    any of them
}