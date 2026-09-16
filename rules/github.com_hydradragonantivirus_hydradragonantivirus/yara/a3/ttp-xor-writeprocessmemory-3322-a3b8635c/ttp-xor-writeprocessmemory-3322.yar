rule TTP_XOR_WriteProcessMemory_3322 {
  strings:
    $key_3322 = { 64 50 [2] 56 72 [2] 50 47 [2] 7e 47 [2] 41 5b }

  condition:
    any of them
}