rule TTP_XOR_WriteProcessMemory_c0f7 {
  strings:
    $key_c0f7 = { 97 85 [2] a5 a7 [2] a3 92 [2] 8d 92 [2] b2 8e }

  condition:
    any of them
}