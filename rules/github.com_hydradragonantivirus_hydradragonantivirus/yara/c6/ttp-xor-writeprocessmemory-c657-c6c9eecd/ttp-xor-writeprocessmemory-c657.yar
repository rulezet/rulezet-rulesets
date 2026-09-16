rule TTP_XOR_WriteProcessMemory_c657 {
  strings:
    $key_c657 = { 91 25 [2] a3 07 [2] a5 32 [2] 8b 32 [2] b4 2e }

  condition:
    any of them
}