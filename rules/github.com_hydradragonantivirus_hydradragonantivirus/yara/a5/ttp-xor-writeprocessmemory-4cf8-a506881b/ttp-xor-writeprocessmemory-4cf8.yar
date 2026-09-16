rule TTP_XOR_WriteProcessMemory_4cf8 {
  strings:
    $key_4cf8 = { 1b 8a [2] 29 a8 [2] 2f 9d [2] 01 9d [2] 3e 81 }

  condition:
    any of them
}