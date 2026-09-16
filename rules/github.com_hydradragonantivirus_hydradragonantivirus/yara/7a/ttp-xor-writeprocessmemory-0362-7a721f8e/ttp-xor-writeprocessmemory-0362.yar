rule TTP_XOR_WriteProcessMemory_0362 {
  strings:
    $key_0362 = { 54 10 [2] 66 32 [2] 60 07 [2] 4e 07 [2] 71 1b }

  condition:
    any of them
}