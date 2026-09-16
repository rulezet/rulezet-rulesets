rule TTP_XOR_WriteProcessMemory_4a71 {
  strings:
    $key_4a71 = { 1d 03 [2] 2f 21 [2] 29 14 [2] 07 14 [2] 38 08 }

  condition:
    any of them
}