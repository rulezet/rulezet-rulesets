rule TTP_XOR_WriteProcessMemory_1d22 {
  strings:
    $key_1d22 = { 4a 50 [2] 78 72 [2] 7e 47 [2] 50 47 [2] 6f 5b }

  condition:
    any of them
}