rule TTP_XOR_WriteProcessMemory_3348 {
  strings:
    $key_3348 = { 64 3a [2] 56 18 [2] 50 2d [2] 7e 2d [2] 41 31 }

  condition:
    any of them
}