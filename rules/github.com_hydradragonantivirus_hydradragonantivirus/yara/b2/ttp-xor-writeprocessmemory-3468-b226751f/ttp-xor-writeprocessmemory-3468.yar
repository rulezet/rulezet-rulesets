rule TTP_XOR_WriteProcessMemory_3468 {
  strings:
    $key_3468 = { 63 1a [2] 51 38 [2] 57 0d [2] 79 0d [2] 46 11 }

  condition:
    any of them
}