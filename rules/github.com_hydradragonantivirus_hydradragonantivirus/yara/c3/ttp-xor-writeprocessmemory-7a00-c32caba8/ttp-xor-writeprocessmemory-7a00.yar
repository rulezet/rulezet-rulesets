rule TTP_XOR_WriteProcessMemory_7a00 {
  strings:
    $key_7a00 = { 2d 72 [2] 1f 50 [2] 19 65 [2] 37 65 [2] 08 79 }

  condition:
    any of them
}