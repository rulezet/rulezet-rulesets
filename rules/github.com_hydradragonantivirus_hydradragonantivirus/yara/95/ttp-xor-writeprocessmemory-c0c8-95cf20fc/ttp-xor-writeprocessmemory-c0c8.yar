rule TTP_XOR_WriteProcessMemory_c0c8 {
  strings:
    $key_c0c8 = { 97 ba [2] a5 98 [2] a3 ad [2] 8d ad [2] b2 b1 }

  condition:
    any of them
}