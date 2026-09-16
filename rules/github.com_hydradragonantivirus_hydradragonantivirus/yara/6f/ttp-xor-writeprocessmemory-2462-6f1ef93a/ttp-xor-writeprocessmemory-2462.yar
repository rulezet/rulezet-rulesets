rule TTP_XOR_WriteProcessMemory_2462 {
  strings:
    $key_2462 = { 73 10 [2] 41 32 [2] 47 07 [2] 69 07 [2] 56 1b }

  condition:
    any of them
}