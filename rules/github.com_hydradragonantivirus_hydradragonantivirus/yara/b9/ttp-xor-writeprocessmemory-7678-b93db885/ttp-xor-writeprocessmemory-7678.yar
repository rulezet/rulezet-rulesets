rule TTP_XOR_WriteProcessMemory_7678 {
  strings:
    $key_7678 = { 21 0a [2] 13 28 [2] 15 1d [2] 3b 1d [2] 04 01 }

  condition:
    any of them
}