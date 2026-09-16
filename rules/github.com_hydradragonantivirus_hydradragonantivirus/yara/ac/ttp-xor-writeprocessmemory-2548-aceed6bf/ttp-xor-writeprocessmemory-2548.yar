rule TTP_XOR_WriteProcessMemory_2548 {
  strings:
    $key_2548 = { 72 3a [2] 40 18 [2] 46 2d [2] 68 2d [2] 57 31 }

  condition:
    any of them
}