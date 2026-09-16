rule TTP_XOR_WriteProcessMemory_7468 {
  strings:
    $key_7468 = { 23 1a [2] 11 38 [2] 17 0d [2] 39 0d [2] 06 11 }

  condition:
    any of them
}