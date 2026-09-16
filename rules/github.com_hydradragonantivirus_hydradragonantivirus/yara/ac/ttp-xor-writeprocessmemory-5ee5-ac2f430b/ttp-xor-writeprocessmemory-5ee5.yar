rule TTP_XOR_WriteProcessMemory_5ee5 {
  strings:
    $key_5ee5 = { 09 97 [2] 3b b5 [2] 3d 80 [2] 13 80 [2] 2c 9c }

  condition:
    any of them
}