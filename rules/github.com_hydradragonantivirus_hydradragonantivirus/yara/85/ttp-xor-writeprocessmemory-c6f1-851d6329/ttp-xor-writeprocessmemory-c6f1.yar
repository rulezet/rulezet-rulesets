rule TTP_XOR_WriteProcessMemory_c6f1 {
  strings:
    $key_c6f1 = { 91 83 [2] a3 a1 [2] a5 94 [2] 8b 94 [2] b4 88 }

  condition:
    any of them
}