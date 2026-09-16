rule TTP_XOR_WriteProcessMemory_ec59 {
  strings:
    $key_ec59 = { bb 2b [2] 89 09 [2] 8f 3c [2] a1 3c [2] 9e 20 }

  condition:
    any of them
}