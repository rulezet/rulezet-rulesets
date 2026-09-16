rule TTP_XOR_WriteProcessMemory_1c78 {
  strings:
    $key_1c78 = { 4b 0a [2] 79 28 [2] 7f 1d [2] 51 1d [2] 6e 01 }

  condition:
    any of them
}