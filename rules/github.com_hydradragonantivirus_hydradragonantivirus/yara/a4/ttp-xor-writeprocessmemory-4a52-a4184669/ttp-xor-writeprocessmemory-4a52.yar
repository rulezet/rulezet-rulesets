rule TTP_XOR_WriteProcessMemory_4a52 {
  strings:
    $key_4a52 = { 1d 20 [2] 2f 02 [2] 29 37 [2] 07 37 [2] 38 2b }

  condition:
    any of them
}