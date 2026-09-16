rule TTP_XOR_WriteProcessMemory_d140 {
  strings:
    $key_d140 = { 86 32 [2] b4 10 [2] b2 25 [2] 9c 25 [2] a3 39 }

  condition:
    any of them
}