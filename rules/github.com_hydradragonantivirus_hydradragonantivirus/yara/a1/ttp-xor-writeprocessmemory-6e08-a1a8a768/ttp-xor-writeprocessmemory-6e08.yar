rule TTP_XOR_WriteProcessMemory_6e08 {
  strings:
    $key_6e08 = { 39 7a [2] 0b 58 [2] 0d 6d [2] 23 6d [2] 1c 71 }

  condition:
    any of them
}