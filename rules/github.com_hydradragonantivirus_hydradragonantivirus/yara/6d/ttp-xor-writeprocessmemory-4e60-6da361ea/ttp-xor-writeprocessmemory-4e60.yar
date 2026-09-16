rule TTP_XOR_WriteProcessMemory_4e60 {
  strings:
    $key_4e60 = { 19 12 [2] 2b 30 [2] 2d 05 [2] 03 05 [2] 3c 19 }

  condition:
    any of them
}