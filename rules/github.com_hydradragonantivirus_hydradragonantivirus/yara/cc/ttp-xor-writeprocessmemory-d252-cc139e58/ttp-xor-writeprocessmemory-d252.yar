rule TTP_XOR_WriteProcessMemory_d252 {
  strings:
    $key_d252 = { 85 20 [2] b7 02 [2] b1 37 [2] 9f 37 [2] a0 2b }

  condition:
    any of them
}