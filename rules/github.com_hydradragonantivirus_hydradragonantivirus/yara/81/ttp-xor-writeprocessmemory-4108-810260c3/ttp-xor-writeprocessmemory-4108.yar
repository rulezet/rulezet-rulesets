rule TTP_XOR_WriteProcessMemory_4108 {
  strings:
    $key_4108 = { 16 7a [2] 24 58 [2] 22 6d [2] 0c 6d [2] 33 71 }

  condition:
    any of them
}