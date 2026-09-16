rule TTP_XOR_WriteProcessMemory_5a48 {
  strings:
    $key_5a48 = { 0d 3a [2] 3f 18 [2] 39 2d [2] 17 2d [2] 28 31 }

  condition:
    any of them
}