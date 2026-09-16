rule TTP_XOR_WriteProcessMemory_1c48 {
  strings:
    $key_1c48 = { 4b 3a [2] 79 18 [2] 7f 2d [2] 51 2d [2] 6e 31 }

  condition:
    any of them
}