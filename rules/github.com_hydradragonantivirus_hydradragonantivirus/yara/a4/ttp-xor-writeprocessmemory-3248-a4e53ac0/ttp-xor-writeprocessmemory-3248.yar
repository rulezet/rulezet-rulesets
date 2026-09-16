rule TTP_XOR_WriteProcessMemory_3248 {
  strings:
    $key_3248 = { 65 3a [2] 57 18 [2] 51 2d [2] 7f 2d [2] 40 31 }

  condition:
    any of them
}