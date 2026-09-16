rule TTP_XOR_WriteProcessMemory_c18c {
  strings:
    $key_c18c = { 96 fe [2] a4 dc [2] a2 e9 [2] 8c e9 [2] b3 f5 }

  condition:
    any of them
}