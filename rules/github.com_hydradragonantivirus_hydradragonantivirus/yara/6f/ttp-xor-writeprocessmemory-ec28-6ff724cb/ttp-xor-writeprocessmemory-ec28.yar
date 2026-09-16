rule TTP_XOR_WriteProcessMemory_ec28 {
  strings:
    $key_ec28 = { bb 5a [2] 89 78 [2] 8f 4d [2] a1 4d [2] 9e 51 }

  condition:
    any of them
}