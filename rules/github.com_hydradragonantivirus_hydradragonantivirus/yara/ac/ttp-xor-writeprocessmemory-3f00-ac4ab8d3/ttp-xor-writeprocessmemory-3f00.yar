rule TTP_XOR_WriteProcessMemory_3f00 {
  strings:
    $key_3f00 = { 68 72 [2] 5a 50 [2] 5c 65 [2] 72 65 [2] 4d 79 }

  condition:
    any of them
}