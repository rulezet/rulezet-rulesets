rule TTP_XOR_WriteProcessMemory_5148 {
  strings:
    $key_5148 = { 06 3a [2] 34 18 [2] 32 2d [2] 1c 2d [2] 23 31 }

  condition:
    any of them
}