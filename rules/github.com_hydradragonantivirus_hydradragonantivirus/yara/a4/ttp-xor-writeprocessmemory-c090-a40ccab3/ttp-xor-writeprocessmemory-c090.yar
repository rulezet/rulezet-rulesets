rule TTP_XOR_WriteProcessMemory_c090 {
  strings:
    $key_c090 = { 97 e2 [2] a5 c0 [2] a3 f5 [2] 8d f5 [2] b2 e9 }

  condition:
    any of them
}