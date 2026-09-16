rule TTP_XOR_WriteProcessMemory_ec62 {
  strings:
    $key_ec62 = { bb 10 [2] 89 32 [2] 8f 07 [2] a1 07 [2] 9e 1b }

  condition:
    any of them
}