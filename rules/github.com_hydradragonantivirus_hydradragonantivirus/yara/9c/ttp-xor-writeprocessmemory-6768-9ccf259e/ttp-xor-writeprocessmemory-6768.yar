rule TTP_XOR_WriteProcessMemory_6768 {
  strings:
    $key_6768 = { 30 1a [2] 02 38 [2] 04 0d [2] 2a 0d [2] 15 11 }

  condition:
    any of them
}