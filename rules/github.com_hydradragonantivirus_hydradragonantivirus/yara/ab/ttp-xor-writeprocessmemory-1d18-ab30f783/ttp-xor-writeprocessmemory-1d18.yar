rule TTP_XOR_WriteProcessMemory_1d18 {
  strings:
    $key_1d18 = { 4a 6a [2] 78 48 [2] 7e 7d [2] 50 7d [2] 6f 61 }

  condition:
    any of them
}