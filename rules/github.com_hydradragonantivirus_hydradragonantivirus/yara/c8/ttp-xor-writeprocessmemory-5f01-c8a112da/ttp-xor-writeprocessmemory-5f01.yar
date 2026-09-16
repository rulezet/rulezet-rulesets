rule TTP_XOR_WriteProcessMemory_5f01 {
  strings:
    $key_5f01 = { 08 73 [2] 3a 51 [2] 3c 64 [2] 12 64 [2] 2d 78 }

  condition:
    any of them
}