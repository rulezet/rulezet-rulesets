rule TTP_XOR_WriteProcessMemory_d25d {
  strings:
    $key_d25d = { 85 2f [2] b7 0d [2] b1 38 [2] 9f 38 [2] a0 24 }

  condition:
    any of them
}