rule TTP_XOR_WriteProcessMemory_2362 {
  strings:
    $key_2362 = { 74 10 [2] 46 32 [2] 40 07 [2] 6e 07 [2] 51 1b }

  condition:
    any of them
}