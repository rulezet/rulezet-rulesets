rule TTP_XOR_WriteProcessMemory_4e67 {
  strings:
    $key_4e67 = { 19 15 [2] 2b 37 [2] 2d 02 [2] 03 02 [2] 3c 1e }

  condition:
    any of them
}