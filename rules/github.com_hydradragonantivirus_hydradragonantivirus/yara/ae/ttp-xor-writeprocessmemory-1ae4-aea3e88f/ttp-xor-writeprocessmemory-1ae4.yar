rule TTP_XOR_WriteProcessMemory_1ae4 {
  strings:
    $key_1ae4 = { 4d 96 [2] 7f b4 [2] 79 81 [2] 57 81 [2] 68 9d }

  condition:
    any of them
}