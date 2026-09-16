rule TTP_XOR_WriteProcessMemory_ec78 {
  strings:
    $key_ec78 = { bb 0a [2] 89 28 [2] 8f 1d [2] a1 1d [2] 9e 01 }

  condition:
    any of them
}