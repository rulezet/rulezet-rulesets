rule TTP_XOR_WriteProcessMemory_ec63 {
  strings:
    $key_ec63 = { bb 11 [2] 89 33 [2] 8f 06 [2] a1 06 [2] 9e 1a }

  condition:
    any of them
}