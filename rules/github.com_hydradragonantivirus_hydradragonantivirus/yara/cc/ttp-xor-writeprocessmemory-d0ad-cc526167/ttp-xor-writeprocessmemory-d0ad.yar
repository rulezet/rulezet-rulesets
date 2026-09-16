rule TTP_XOR_WriteProcessMemory_d0ad {
  strings:
    $key_d0ad = { 87 df [2] b5 fd [2] b3 c8 [2] 9d c8 [2] a2 d4 }

  condition:
    any of them
}