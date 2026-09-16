rule TTP_XOR_WriteProcessMemory_1d48 {
  strings:
    $key_1d48 = { 4a 3a [2] 78 18 [2] 7e 2d [2] 50 2d [2] 6f 31 }

  condition:
    any of them
}