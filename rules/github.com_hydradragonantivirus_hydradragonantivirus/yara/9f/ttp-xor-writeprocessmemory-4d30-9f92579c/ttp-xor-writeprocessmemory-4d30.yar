rule TTP_XOR_WriteProcessMemory_4d30 {
  strings:
    $key_4d30 = { 1a 42 [2] 28 60 [2] 2e 55 [2] 00 55 [2] 3f 49 }

  condition:
    any of them
}