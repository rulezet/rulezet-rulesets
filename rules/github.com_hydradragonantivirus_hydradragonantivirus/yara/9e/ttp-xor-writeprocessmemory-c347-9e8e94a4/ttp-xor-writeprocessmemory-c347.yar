rule TTP_XOR_WriteProcessMemory_c347 {
  strings:
    $key_c347 = { 94 35 [2] a6 17 [2] a0 22 [2] 8e 22 [2] b1 3e }

  condition:
    any of them
}