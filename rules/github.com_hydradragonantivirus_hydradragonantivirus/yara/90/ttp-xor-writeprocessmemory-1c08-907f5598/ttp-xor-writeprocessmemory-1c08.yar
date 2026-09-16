rule TTP_XOR_WriteProcessMemory_1c08 {
  strings:
    $key_1c08 = { 4b 7a [2] 79 58 [2] 7f 6d [2] 51 6d [2] 6e 71 }

  condition:
    any of them
}