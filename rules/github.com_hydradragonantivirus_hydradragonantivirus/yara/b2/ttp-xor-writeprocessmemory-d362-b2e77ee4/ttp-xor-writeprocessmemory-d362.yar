rule TTP_XOR_WriteProcessMemory_d362 {
  strings:
    $key_d362 = { 84 10 [2] b6 32 [2] b0 07 [2] 9e 07 [2] a1 1b }

  condition:
    any of them
}