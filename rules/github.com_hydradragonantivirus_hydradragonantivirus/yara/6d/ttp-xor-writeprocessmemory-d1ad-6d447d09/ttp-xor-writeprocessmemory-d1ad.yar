rule TTP_XOR_WriteProcessMemory_d1ad {
  strings:
    $key_d1ad = { 86 df [2] b4 fd [2] b2 c8 [2] 9c c8 [2] a3 d4 }

  condition:
    any of them
}