rule TTP_XOR_WriteProcessMemory_5448 {
  strings:
    $key_5448 = { 03 3a [2] 31 18 [2] 37 2d [2] 19 2d [2] 26 31 }

  condition:
    any of them
}