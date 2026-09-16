rule TTP_XOR_WriteProcessMemory_ec32 {
  strings:
    $key_ec32 = { bb 40 [2] 89 62 [2] 8f 57 [2] a1 57 [2] 9e 4b }

  condition:
    any of them
}