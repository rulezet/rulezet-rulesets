rule TTP_XOR_WriteProcessMemory_d762 {
  strings:
    $key_d762 = { 80 10 [2] b2 32 [2] b4 07 [2] 9a 07 [2] a5 1b }

  condition:
    any of them
}