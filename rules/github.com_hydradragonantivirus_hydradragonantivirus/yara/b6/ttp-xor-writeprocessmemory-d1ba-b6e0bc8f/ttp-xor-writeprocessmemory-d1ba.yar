rule TTP_XOR_WriteProcessMemory_d1ba {
  strings:
    $key_d1ba = { 86 c8 [2] b4 ea [2] b2 df [2] 9c df [2] a3 c3 }

  condition:
    any of them
}