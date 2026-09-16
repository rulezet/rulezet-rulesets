rule TTP_XOR_WriteProcessMemory_2b62 {
  strings:
    $key_2b62 = { 7c 10 [2] 4e 32 [2] 48 07 [2] 66 07 [2] 59 1b }

  condition:
    any of them
}