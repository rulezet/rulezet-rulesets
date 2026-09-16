rule TTP_XOR_WriteProcessMemory_7a71 {
  strings:
    $key_7a71 = { 2d 03 [2] 1f 21 [2] 19 14 [2] 37 14 [2] 08 08 }

  condition:
    any of them
}