rule TTP_XOR_WriteProcessMemory_1ae1 {
  strings:
    $key_1ae1 = { 4d 93 [2] 7f b1 [2] 79 84 [2] 57 84 [2] 68 98 }

  condition:
    any of them
}