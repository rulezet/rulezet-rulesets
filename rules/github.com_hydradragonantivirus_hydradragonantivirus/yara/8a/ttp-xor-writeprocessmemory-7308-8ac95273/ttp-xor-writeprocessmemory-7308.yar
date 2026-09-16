rule TTP_XOR_WriteProcessMemory_7308 {
  strings:
    $key_7308 = { 24 7a [2] 16 58 [2] 10 6d [2] 3e 6d [2] 01 71 }

  condition:
    any of them
}