rule TTP_XOR_WriteProcessMemory_c68c {
  strings:
    $key_c68c = { 91 fe [2] a3 dc [2] a5 e9 [2] 8b e9 [2] b4 f5 }

  condition:
    any of them
}