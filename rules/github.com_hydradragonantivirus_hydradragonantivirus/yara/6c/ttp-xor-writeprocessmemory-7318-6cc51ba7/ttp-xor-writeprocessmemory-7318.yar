rule TTP_XOR_WriteProcessMemory_7318 {
  strings:
    $key_7318 = { 24 6a [2] 16 48 [2] 10 7d [2] 3e 7d [2] 01 61 }

  condition:
    any of them
}