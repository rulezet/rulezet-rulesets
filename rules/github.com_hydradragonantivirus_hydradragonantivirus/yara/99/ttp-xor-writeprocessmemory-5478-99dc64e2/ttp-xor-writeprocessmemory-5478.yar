rule TTP_XOR_WriteProcessMemory_5478 {
  strings:
    $key_5478 = { 03 0a [2] 31 28 [2] 37 1d [2] 19 1d [2] 26 01 }

  condition:
    any of them
}