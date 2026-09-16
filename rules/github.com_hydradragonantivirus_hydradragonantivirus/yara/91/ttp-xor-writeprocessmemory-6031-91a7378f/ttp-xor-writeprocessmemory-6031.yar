rule TTP_XOR_WriteProcessMemory_6031 {
  strings:
    $key_6031 = { 37 43 [2] 05 61 [2] 03 54 [2] 2d 54 [2] 12 48 }

  condition:
    any of them
}