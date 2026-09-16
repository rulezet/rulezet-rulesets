rule TTP_XOR_WriteProcessMemory_ec51 {
  strings:
    $key_ec51 = { bb 23 [2] 89 01 [2] 8f 34 [2] a1 34 [2] 9e 28 }

  condition:
    any of them
}