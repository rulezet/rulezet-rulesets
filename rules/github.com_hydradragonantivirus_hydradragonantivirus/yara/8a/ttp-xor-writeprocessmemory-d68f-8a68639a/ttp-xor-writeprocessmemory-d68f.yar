rule TTP_XOR_WriteProcessMemory_d68f {
  strings:
    $key_d68f = { 81 fd [2] b3 df [2] b5 ea [2] 9b ea [2] a4 f6 }

  condition:
    any of them
}