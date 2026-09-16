rule TTP_XOR_WriteProcessMemory_5318 {
  strings:
    $key_5318 = { 04 6a [2] 36 48 [2] 30 7d [2] 1e 7d [2] 21 61 }

  condition:
    any of them
}