rule TTP_XOR_WriteProcessMemory_0668 {
  strings:
    $key_0668 = { 51 1a [2] 63 38 [2] 65 0d [2] 4b 0d [2] 74 11 }

  condition:
    any of them
}