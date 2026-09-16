rule TTP_XOR_WriteProcessMemory_1e68 {
  strings:
    $key_1e68 = { 49 1a [2] 7b 38 [2] 7d 0d [2] 53 0d [2] 6c 11 }

  condition:
    any of them
}