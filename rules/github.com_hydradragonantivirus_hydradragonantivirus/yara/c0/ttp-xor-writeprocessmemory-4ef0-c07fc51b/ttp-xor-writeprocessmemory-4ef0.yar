rule TTP_XOR_WriteProcessMemory_4ef0 {
  strings:
    $key_4ef0 = { 19 82 [2] 2b a0 [2] 2d 95 [2] 03 95 [2] 3c 89 }

  condition:
    any of them
}