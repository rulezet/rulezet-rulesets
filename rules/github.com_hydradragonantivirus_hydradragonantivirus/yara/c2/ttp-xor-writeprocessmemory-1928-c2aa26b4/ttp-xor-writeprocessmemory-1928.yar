rule TTP_XOR_WriteProcessMemory_1928 {
  strings:
    $key_1928 = { 4e 5a [2] 7c 78 [2] 7a 4d [2] 54 4d [2] 6b 51 }

  condition:
    any of them
}