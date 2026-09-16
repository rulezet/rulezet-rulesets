rule TTP_XOR_WriteProcessMemory_c040 {
  strings:
    $key_c040 = { 97 32 [2] a5 10 [2] a3 25 [2] 8d 25 [2] b2 39 }

  condition:
    any of them
}