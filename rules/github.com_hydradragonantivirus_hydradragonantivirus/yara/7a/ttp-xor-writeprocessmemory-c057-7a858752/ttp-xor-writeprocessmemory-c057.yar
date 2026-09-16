rule TTP_XOR_WriteProcessMemory_c057 {
  strings:
    $key_c057 = { 97 25 [2] a5 07 [2] a3 32 [2] 8d 32 [2] b2 2e }

  condition:
    any of them
}