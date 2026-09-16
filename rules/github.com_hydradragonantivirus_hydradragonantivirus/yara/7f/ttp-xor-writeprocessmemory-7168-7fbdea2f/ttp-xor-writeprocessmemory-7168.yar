rule TTP_XOR_WriteProcessMemory_7168 {
  strings:
    $key_7168 = { 26 1a [2] 14 38 [2] 12 0d [2] 3c 0d [2] 03 11 }

  condition:
    any of them
}