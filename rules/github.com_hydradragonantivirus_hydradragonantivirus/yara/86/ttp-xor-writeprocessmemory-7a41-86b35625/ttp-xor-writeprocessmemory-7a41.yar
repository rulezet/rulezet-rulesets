rule TTP_XOR_WriteProcessMemory_7a41 {
  strings:
    $key_7a41 = { 2d 33 [2] 1f 11 [2] 19 24 [2] 37 24 [2] 08 38 }

  condition:
    any of them
}