rule TTP_XOR_WriteProcessMemory_ec52 {
  strings:
    $key_ec52 = { bb 20 [2] 89 02 [2] 8f 37 [2] a1 37 [2] 9e 2b }

  condition:
    any of them
}