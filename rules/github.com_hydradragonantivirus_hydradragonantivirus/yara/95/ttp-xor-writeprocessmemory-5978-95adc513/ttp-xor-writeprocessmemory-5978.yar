rule TTP_XOR_WriteProcessMemory_5978 {
  strings:
    $key_5978 = { 0e 0a [2] 3c 28 [2] 3a 1d [2] 14 1d [2] 2b 01 }

  condition:
    any of them
}