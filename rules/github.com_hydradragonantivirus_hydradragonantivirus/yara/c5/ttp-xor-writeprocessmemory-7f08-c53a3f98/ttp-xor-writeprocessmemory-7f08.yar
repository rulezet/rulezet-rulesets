rule TTP_XOR_WriteProcessMemory_7f08 {
  strings:
    $key_7f08 = { 28 7a [2] 1a 58 [2] 1c 6d [2] 32 6d [2] 0d 71 }

  condition:
    any of them
}