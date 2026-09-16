rule TTP_XOR_WriteProcessMemory_ec11 {
  strings:
    $key_ec11 = { bb 63 [2] 89 41 [2] 8f 74 [2] a1 74 [2] 9e 68 }

  condition:
    any of them
}