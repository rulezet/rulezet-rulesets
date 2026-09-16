rule TTP_XOR_WriteProcessMemory_d162 {
  strings:
    $key_d162 = { 86 10 [2] b4 32 [2] b2 07 [2] 9c 07 [2] a3 1b }

  condition:
    any of them
}