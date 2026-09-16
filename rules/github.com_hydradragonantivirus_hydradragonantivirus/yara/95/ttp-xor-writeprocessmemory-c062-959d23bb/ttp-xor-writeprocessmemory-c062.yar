rule TTP_XOR_WriteProcessMemory_c062 {
  strings:
    $key_c062 = { 97 10 [2] a5 32 [2] a3 07 [2] 8d 07 [2] b2 1b }

  condition:
    any of them
}