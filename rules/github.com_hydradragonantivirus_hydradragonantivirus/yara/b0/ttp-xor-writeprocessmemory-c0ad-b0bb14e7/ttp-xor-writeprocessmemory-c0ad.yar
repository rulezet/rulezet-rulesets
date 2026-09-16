rule TTP_XOR_WriteProcessMemory_c0ad {
  strings:
    $key_c0ad = { 97 df [2] a5 fd [2] a3 c8 [2] 8d c8 [2] b2 d4 }

  condition:
    any of them
}