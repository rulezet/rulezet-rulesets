rule TTP_XOR_WriteProcessMemory_6051 {
  strings:
    $key_6051 = { 37 23 [2] 05 01 [2] 03 34 [2] 2d 34 [2] 12 28 }

  condition:
    any of them
}