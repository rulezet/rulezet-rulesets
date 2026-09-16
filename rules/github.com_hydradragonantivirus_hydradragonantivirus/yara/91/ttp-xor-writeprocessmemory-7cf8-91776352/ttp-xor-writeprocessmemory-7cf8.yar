rule TTP_XOR_WriteProcessMemory_7cf8 {
  strings:
    $key_7cf8 = { 2b 8a [2] 19 a8 [2] 1f 9d [2] 31 9d [2] 0e 81 }

  condition:
    any of them
}