rule TTP_XOR_WriteProcessMemory_e462 {
  strings:
    $key_e462 = { b3 10 [2] 81 32 [2] 87 07 [2] a9 07 [2] 96 1b }

  condition:
    any of them
}