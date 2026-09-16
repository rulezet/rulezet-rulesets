rule TTP_XOR_WriteProcessMemory_1948 {
  strings:
    $key_1948 = { 4e 3a [2] 7c 18 [2] 7a 2d [2] 54 2d [2] 6b 31 }

  condition:
    any of them
}