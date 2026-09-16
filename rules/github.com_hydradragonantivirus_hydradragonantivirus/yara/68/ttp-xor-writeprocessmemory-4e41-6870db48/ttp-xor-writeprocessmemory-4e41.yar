rule TTP_XOR_WriteProcessMemory_4e41 {
  strings:
    $key_4e41 = { 19 33 [2] 2b 11 [2] 2d 24 [2] 03 24 [2] 3c 38 }

  condition:
    any of them
}