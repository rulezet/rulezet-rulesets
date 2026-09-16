rule TTP_XOR_WriteProcessMemory_d0c8 {
  strings:
    $key_d0c8 = { 87 ba [2] b5 98 [2] b3 ad [2] 9d ad [2] a2 b1 }

  condition:
    any of them
}