rule TTP_XOR_WriteProcessMemory_0e68 {
  strings:
    $key_0e68 = { 59 1a [2] 6b 38 [2] 6d 0d [2] 43 0d [2] 7c 11 }

  condition:
    any of them
}