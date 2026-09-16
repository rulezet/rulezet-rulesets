rule TTP_XOR_WriteProcessMemory_d18c {
  strings:
    $key_d18c = { 86 fe [2] b4 dc [2] b2 e9 [2] 9c e9 [2] a3 f5 }

  condition:
    any of them
}