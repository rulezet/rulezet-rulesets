rule TTP_XOR_WriteProcessMemory_4408 {
  strings:
    $key_4408 = { 13 7a [2] 21 58 [2] 27 6d [2] 09 6d [2] 36 71 }

  condition:
    any of them
}