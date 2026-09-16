rule TTP_XOR_WriteProcessMemory_2a68 {
  strings:
    $key_2a68 = { 7d 1a [2] 4f 38 [2] 49 0d [2] 67 0d [2] 58 11 }

  condition:
    any of them
}