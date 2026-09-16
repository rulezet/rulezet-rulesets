rule TTP_XOR_WriteProcessMemory_5bf8 {
  strings:
    $key_5bf8 = { 0c 8a [2] 3e a8 [2] 38 9d [2] 16 9d [2] 29 81 }

  condition:
    any of them
}