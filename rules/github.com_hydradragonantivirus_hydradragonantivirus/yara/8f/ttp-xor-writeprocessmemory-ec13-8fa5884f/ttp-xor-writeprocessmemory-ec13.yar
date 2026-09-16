rule TTP_XOR_WriteProcessMemory_ec13 {
  strings:
    $key_ec13 = { bb 61 [2] 89 43 [2] 8f 76 [2] a1 76 [2] 9e 6a }

  condition:
    any of them
}