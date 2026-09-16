rule TTP_XOR_WriteProcessMemory_d48c {
  strings:
    $key_d48c = { 83 fe [2] b1 dc [2] b7 e9 [2] 99 e9 [2] a6 f5 }

  condition:
    any of them
}