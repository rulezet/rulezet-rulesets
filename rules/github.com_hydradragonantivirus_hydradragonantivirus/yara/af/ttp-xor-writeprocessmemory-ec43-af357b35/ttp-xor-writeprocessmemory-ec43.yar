rule TTP_XOR_WriteProcessMemory_ec43 {
  strings:
    $key_ec43 = { bb 31 [2] 89 13 [2] 8f 26 [2] a1 26 [2] 9e 3a }

  condition:
    any of them
}