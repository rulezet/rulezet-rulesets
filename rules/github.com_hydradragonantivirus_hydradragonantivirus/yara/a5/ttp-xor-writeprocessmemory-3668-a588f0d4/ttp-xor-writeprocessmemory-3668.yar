rule TTP_XOR_WriteProcessMemory_3668 {
  strings:
    $key_3668 = { 61 1a [2] 53 38 [2] 55 0d [2] 7b 0d [2] 44 11 }

  condition:
    any of them
}