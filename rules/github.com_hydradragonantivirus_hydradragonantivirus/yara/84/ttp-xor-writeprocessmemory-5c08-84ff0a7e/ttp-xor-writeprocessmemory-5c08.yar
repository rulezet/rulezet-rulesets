rule TTP_XOR_WriteProcessMemory_5c08 {
  strings:
    $key_5c08 = { 0b 7a [2] 39 58 [2] 3f 6d [2] 11 6d [2] 2e 71 }

  condition:
    any of them
}