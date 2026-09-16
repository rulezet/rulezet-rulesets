rule TTP_XOR_WriteProcessMemory_5648 {
  strings:
    $key_5648 = { 01 3a [2] 33 18 [2] 35 2d [2] 1b 2d [2] 24 31 }

  condition:
    any of them
}