rule TTP_XOR_WriteProcessMemory_ec18 {
  strings:
    $key_ec18 = { bb 6a [2] 89 48 [2] 8f 7d [2] a1 7d [2] 9e 61 }

  condition:
    any of them
}