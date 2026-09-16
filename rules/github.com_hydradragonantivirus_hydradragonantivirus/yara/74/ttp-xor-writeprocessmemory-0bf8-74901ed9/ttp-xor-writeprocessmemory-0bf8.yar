rule TTP_XOR_WriteProcessMemory_0bf8 {
  strings:
    $key_0bf8 = { 5c 8a [2] 6e a8 [2] 68 9d [2] 46 9d [2] 79 81 }

  condition:
    any of them
}