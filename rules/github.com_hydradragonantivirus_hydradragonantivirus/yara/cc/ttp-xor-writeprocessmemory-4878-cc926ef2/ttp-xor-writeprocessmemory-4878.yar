rule TTP_XOR_WriteProcessMemory_4878 {
  strings:
    $key_4878 = { 1f 0a [2] 2d 28 [2] 2b 1d [2] 05 1d [2] 3a 01 }

  condition:
    any of them
}