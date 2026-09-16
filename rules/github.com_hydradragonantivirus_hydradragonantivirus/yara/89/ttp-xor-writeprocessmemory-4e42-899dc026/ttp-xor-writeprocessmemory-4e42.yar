rule TTP_XOR_WriteProcessMemory_4e42 {
  strings:
    $key_4e42 = { 19 30 [2] 2b 12 [2] 2d 27 [2] 03 27 [2] 3c 3b }

  condition:
    any of them
}