rule TTP_XOR_WriteProcessMemory_ec73 {
  strings:
    $key_ec73 = { bb 01 [2] 89 23 [2] 8f 16 [2] a1 16 [2] 9e 0a }

  condition:
    any of them
}