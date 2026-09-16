rule TTP_XOR_WriteProcessMemory_7ff8 {
  strings:
    $key_7ff8 = { 28 8a [2] 1a a8 [2] 1c 9d [2] 32 9d [2] 0d 81 }

  condition:
    any of them
}