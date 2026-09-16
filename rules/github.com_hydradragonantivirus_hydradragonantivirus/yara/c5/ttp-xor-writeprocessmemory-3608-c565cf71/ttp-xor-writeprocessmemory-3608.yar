rule TTP_XOR_WriteProcessMemory_3608 {
  strings:
    $key_3608 = { 61 7a [2] 53 58 [2] 55 6d [2] 7b 6d [2] 44 71 }

  condition:
    any of them
}