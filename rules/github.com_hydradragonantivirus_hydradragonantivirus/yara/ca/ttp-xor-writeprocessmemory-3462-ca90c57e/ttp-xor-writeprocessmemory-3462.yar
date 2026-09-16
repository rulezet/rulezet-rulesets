rule TTP_XOR_WriteProcessMemory_3462 {
  strings:
    $key_3462 = { 63 10 [2] 51 32 [2] 57 07 [2] 79 07 [2] 46 1b }

  condition:
    any of them
}