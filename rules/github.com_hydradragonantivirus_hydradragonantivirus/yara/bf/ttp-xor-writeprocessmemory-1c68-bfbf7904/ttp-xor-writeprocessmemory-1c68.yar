rule TTP_XOR_WriteProcessMemory_1c68 {
  strings:
    $key_1c68 = { 4b 1a [2] 79 38 [2] 7f 0d [2] 51 0d [2] 6e 11 }

  condition:
    any of them
}