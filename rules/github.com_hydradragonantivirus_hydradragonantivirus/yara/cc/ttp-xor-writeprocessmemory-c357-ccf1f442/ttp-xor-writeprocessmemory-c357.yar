rule TTP_XOR_WriteProcessMemory_c357 {
  strings:
    $key_c357 = { 94 25 [2] a6 07 [2] a0 32 [2] 8e 32 [2] b1 2e }

  condition:
    any of them
}