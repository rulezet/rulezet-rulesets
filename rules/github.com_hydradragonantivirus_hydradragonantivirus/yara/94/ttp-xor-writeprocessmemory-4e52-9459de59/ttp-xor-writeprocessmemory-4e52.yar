rule TTP_XOR_WriteProcessMemory_4e52 {
  strings:
    $key_4e52 = { 19 20 [2] 2b 02 [2] 2d 37 [2] 03 37 [2] 3c 2b }

  condition:
    any of them
}