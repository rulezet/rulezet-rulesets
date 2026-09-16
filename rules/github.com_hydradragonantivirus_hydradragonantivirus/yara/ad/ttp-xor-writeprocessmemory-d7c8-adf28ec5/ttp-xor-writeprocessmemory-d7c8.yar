rule TTP_XOR_WriteProcessMemory_d7c8 {
  strings:
    $key_d7c8 = { 80 ba [2] b2 98 [2] b4 ad [2] 9a ad [2] a5 b1 }

  condition:
    any of them
}