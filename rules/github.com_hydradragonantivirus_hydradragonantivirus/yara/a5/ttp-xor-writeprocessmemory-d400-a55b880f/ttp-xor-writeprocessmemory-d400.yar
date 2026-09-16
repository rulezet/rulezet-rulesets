rule TTP_XOR_WriteProcessMemory_d400 {
  strings:
    $key_d400 = { 83 72 [2] b1 50 [2] b7 65 [2] 99 65 [2] a6 79 }

  condition:
    any of them
}