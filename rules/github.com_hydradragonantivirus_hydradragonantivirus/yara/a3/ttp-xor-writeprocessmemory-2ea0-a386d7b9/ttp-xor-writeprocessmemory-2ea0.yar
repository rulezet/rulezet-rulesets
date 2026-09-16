rule TTP_XOR_WriteProcessMemory_2ea0 {
  strings:
    $key_2ea0 = { 79 d2 [2] 4b f0 [2] 4d c5 [2] 63 c5 [2] 5c d9 }

  condition:
    any of them
}