rule TTP_XOR_WriteProcessMemory_2308 {
  strings:
    $key_2308 = { 74 7a [2] 46 58 [2] 40 6d [2] 6e 6d [2] 51 71 }

  condition:
    any of them
}