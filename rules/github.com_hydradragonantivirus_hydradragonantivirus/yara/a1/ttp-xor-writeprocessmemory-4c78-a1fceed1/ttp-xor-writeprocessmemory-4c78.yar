rule TTP_XOR_WriteProcessMemory_4c78 {
  strings:
    $key_4c78 = { 1b 0a [2] 29 28 [2] 2f 1d [2] 01 1d [2] 3e 01 }

  condition:
    any of them
}