rule TTP_XOR_WriteProcessMemory_d1c8 {
  strings:
    $key_d1c8 = { 86 ba [2] b4 98 [2] b2 ad [2] 9c ad [2] a3 b1 }

  condition:
    any of them
}