rule TTP_XOR_WriteProcessMemory_5928 {
  strings:
    $key_5928 = { 0e 5a [2] 3c 78 [2] 3a 4d [2] 14 4d [2] 2b 51 }

  condition:
    any of them
}