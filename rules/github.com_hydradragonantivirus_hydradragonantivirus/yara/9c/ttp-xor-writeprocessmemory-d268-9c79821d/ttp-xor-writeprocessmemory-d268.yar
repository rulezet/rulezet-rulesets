rule TTP_XOR_WriteProcessMemory_d268 {
  strings:
    $key_d268 = { 85 1a [2] b7 38 [2] b1 0d [2] 9f 0d [2] a0 11 }

  condition:
    any of them
}