rule TTP_XOR_WriteProcessMemory_4ef1 {
  strings:
    $key_4ef1 = { 19 83 [2] 2b a1 [2] 2d 94 [2] 03 94 [2] 3c 88 }

  condition:
    any of them
}