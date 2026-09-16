rule TTP_XOR_WriteProcessMemory_7a08 {
  strings:
    $key_7a08 = { 2d 7a [2] 1f 58 [2] 19 6d [2] 37 6d [2] 08 71 }

  condition:
    any of them
}