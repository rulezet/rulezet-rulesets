rule TTP_XOR_WriteProcessMemory_4ef9 {
  strings:
    $key_4ef9 = { 19 8b [2] 2b a9 [2] 2d 9c [2] 03 9c [2] 3c 80 }

  condition:
    any of them
}