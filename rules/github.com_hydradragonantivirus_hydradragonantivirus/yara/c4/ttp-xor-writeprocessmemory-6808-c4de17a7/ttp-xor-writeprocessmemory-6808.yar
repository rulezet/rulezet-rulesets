rule TTP_XOR_WriteProcessMemory_6808 {
  strings:
    $key_6808 = { 3f 7a [2] 0d 58 [2] 0b 6d [2] 25 6d [2] 1a 71 }

  condition:
    any of them
}