rule TTP_XOR_WriteProcessMemory_4a02 {
  strings:
    $key_4a02 = { 1d 70 [2] 2f 52 [2] 29 67 [2] 07 67 [2] 38 7b }

  condition:
    any of them
}