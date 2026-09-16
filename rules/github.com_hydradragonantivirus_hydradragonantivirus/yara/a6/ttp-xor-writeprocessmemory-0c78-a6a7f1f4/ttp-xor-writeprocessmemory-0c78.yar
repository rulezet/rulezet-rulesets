rule TTP_XOR_WriteProcessMemory_0c78 {
  strings:
    $key_0c78 = { 5b 0a [2] 69 28 [2] 6f 1d [2] 41 1d [2] 7e 01 }

  condition:
    any of them
}