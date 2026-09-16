rule TTP_XOR_WriteProcessMemory_c0f2 {
  strings:
    $key_c0f2 = { 97 80 [2] a5 a2 [2] a3 97 [2] 8d 97 [2] b2 8b }

  condition:
    any of them
}