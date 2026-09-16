rule TTP_XOR_WriteProcessMemory_7551 {
  strings:
    $key_7551 = { 22 23 [2] 10 01 [2] 16 34 [2] 38 34 [2] 07 28 }

  condition:
    any of them
}