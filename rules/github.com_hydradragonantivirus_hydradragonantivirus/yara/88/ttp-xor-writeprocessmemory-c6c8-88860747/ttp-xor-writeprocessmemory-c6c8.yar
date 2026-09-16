rule TTP_XOR_WriteProcessMemory_c6c8 {
  strings:
    $key_c6c8 = { 91 ba [2] a3 98 [2] a5 ad [2] 8b ad [2] b4 b1 }

  condition:
    any of them
}