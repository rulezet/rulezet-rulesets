rule TTP_XOR_WriteProcessMemory_6c78 {
  strings:
    $key_6c78 = { 3b 0a [2] 09 28 [2] 0f 1d [2] 21 1d [2] 1e 01 }

  condition:
    any of them
}