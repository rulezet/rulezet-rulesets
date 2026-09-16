rule TTP_XOR_WriteProcessMemory_5df8 {
  strings:
    $key_5df8 = { 0a 8a [2] 38 a8 [2] 3e 9d [2] 10 9d [2] 2f 81 }

  condition:
    any of them
}