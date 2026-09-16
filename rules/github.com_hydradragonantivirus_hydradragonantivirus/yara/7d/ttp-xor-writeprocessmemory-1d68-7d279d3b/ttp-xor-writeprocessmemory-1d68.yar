rule TTP_XOR_WriteProcessMemory_1d68 {
  strings:
    $key_1d68 = { 4a 1a [2] 78 38 [2] 7e 0d [2] 50 0d [2] 6f 11 }

  condition:
    any of them
}