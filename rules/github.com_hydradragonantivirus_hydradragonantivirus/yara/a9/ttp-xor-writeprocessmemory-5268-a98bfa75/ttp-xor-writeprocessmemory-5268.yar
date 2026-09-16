rule TTP_XOR_WriteProcessMemory_5268 {
  strings:
    $key_5268 = { 05 1a [2] 37 38 [2] 31 0d [2] 1f 0d [2] 20 11 }

  condition:
    any of them
}