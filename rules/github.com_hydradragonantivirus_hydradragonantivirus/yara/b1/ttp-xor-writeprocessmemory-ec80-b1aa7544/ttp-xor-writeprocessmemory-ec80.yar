rule TTP_XOR_WriteProcessMemory_ec80 {
  strings:
    $key_ec80 = { bb f2 [2] 89 d0 [2] 8f e5 [2] a1 e5 [2] 9e f9 }

  condition:
    any of them
}