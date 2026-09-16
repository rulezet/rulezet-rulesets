rule TTP_XOR_WriteProcessMemory_c0c3 {
  strings:
    $key_c0c3 = { 97 b1 [2] a5 93 [2] a3 a6 [2] 8d a6 [2] b2 ba }

  condition:
    any of them
}