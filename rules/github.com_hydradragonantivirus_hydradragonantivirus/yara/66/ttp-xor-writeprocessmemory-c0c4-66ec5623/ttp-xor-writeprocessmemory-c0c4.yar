rule TTP_XOR_WriteProcessMemory_c0c4 {
  strings:
    $key_c0c4 = { 97 b6 [2] a5 94 [2] a3 a1 [2] 8d a1 [2] b2 bd }

  condition:
    any of them
}