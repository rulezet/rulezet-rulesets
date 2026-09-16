rule TTP_XOR_WriteProcessMemory_4df8 {
  strings:
    $key_4df8 = { 1a 8a [2] 28 a8 [2] 2e 9d [2] 00 9d [2] 3f 81 }

  condition:
    any of them
}