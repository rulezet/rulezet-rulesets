rule TTP_XOR_WriteProcessMemory_d062 {
  strings:
    $key_d062 = { 87 10 [2] b5 32 [2] b3 07 [2] 9d 07 [2] a2 1b }

  condition:
    any of them
}