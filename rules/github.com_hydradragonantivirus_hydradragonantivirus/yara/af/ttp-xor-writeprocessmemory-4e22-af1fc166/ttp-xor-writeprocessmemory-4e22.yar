rule TTP_XOR_WriteProcessMemory_4e22 {
  strings:
    $key_4e22 = { 19 50 [2] 2b 72 [2] 2d 47 [2] 03 47 [2] 3c 5b }

  condition:
    any of them
}