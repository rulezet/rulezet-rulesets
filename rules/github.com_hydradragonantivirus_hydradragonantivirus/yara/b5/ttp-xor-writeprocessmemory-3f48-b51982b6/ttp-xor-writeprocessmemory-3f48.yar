rule TTP_XOR_WriteProcessMemory_3f48 {
  strings:
    $key_3f48 = { 68 3a [2] 5a 18 [2] 5c 2d [2] 72 2d [2] 4d 31 }

  condition:
    any of them
}