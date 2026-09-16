rule TTP_XOR_WriteProcessMemory_c337 {
  strings:
    $key_c337 = { 94 45 [2] a6 67 [2] a0 52 [2] 8e 52 [2] b1 4e }

  condition:
    any of them
}