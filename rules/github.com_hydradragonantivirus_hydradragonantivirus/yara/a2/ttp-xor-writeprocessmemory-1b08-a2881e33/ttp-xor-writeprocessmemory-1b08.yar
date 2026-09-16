rule TTP_XOR_WriteProcessMemory_1b08 {
  strings:
    $key_1b08 = { 4c 7a [2] 7e 58 [2] 78 6d [2] 56 6d [2] 69 71 }

  condition:
    any of them
}