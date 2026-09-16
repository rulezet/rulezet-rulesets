rule TTP_XOR_WriteProcessMemory_2608 {
  strings:
    $key_2608 = { 71 7a [2] 43 58 [2] 45 6d [2] 6b 6d [2] 54 71 }

  condition:
    any of them
}