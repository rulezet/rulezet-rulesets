rule TTP_XOR_WriteProcessMemory_78f8 {
  strings:
    $key_78f8 = { 2f 8a [2] 1d a8 [2] 1b 9d [2] 35 9d [2] 0a 81 }

  condition:
    any of them
}