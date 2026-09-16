rule TTP_XOR_WriteProcessMemory_c655 {
  strings:
    $key_c655 = { 91 27 [2] a3 05 [2] a5 30 [2] 8b 30 [2] b4 2c }

  condition:
    any of them
}