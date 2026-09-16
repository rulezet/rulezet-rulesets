rule TTP_XOR_WriteProcessMemory_6001 {
  strings:
    $key_6001 = { 37 73 [2] 05 51 [2] 03 64 [2] 2d 64 [2] 12 78 }

  condition:
    any of them
}