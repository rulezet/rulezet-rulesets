rule TTP_XOR_WriteProcessMemory_d741 {
  strings:
    $key_d741 = { 80 33 [2] b2 11 [2] b4 24 [2] 9a 24 [2] a5 38 }

  condition:
    any of them
}