rule TTP_XOR_WriteProcessMemory_6017 {
  strings:
    $key_6017 = { 37 65 [2] 05 47 [2] 03 72 [2] 2d 72 [2] 12 6e }

  condition:
    any of them
}