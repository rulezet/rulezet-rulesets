rule TTP_XOR_WriteProcessMemory_1e48 {
  strings:
    $key_1e48 = { 49 3a [2] 7b 18 [2] 7d 2d [2] 53 2d [2] 6c 31 }

  condition:
    any of them
}