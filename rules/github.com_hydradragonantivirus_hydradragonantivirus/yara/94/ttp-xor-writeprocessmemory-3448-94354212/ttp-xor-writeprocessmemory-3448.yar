rule TTP_XOR_WriteProcessMemory_3448 {
  strings:
    $key_3448 = { 63 3a [2] 51 18 [2] 57 2d [2] 79 2d [2] 46 31 }

  condition:
    any of them
}