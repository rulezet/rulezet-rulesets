rule TTP_XOR_WriteProcessMemory_0462 {
  strings:
    $key_0462 = { 53 10 [2] 61 32 [2] 67 07 [2] 49 07 [2] 76 1b }

  condition:
    any of them
}