rule TTP_XOR_WriteProcessMemory_2448 {
  strings:
    $key_2448 = { 73 3a [2] 41 18 [2] 47 2d [2] 69 2d [2] 56 31 }

  condition:
    any of them
}