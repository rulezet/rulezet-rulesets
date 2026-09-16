rule TTP_XOR_WriteProcessMemory_6067 {
  strings:
    $key_6067 = { 37 15 [2] 05 37 [2] 03 02 [2] 2d 02 [2] 12 1e }

  condition:
    any of them
}