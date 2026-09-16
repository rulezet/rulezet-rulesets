rule TTP_XOR_WriteProcessMemory_1b48 {
  strings:
    $key_1b48 = { 4c 3a [2] 7e 18 [2] 78 2d [2] 56 2d [2] 69 31 }

  condition:
    any of them
}