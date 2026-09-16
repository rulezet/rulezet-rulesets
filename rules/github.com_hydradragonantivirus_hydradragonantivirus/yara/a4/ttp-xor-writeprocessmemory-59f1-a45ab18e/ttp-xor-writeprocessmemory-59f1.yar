rule TTP_XOR_WriteProcessMemory_59f1 {
  strings:
    $key_59f1 = { 0e 83 [2] 3c a1 [2] 3a 94 [2] 14 94 [2] 2b 88 }

  condition:
    any of them
}