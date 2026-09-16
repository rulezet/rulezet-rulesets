rule TTP_XOR_WriteProcessMemory_0248 {
  strings:
    $key_0248 = { 55 3a [2] 67 18 [2] 61 2d [2] 4f 2d [2] 70 31 }

  condition:
    any of them
}