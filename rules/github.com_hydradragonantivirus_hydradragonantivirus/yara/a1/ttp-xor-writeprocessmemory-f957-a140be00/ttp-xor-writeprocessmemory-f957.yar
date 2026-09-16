rule TTP_XOR_WriteProcessMemory_f957 {
  strings:
    $key_f957 = { ae 25 [2] 9c 07 [2] 9a 32 [2] b4 32 [2] 8b 2e }

  condition:
    any of them
}