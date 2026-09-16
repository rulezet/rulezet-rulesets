rule TTP_XOR_WriteProcessMemory_70e5 {
  strings:
    $key_70e5 = { 27 97 [2] 15 b5 [2] 13 80 [2] 3d 80 [2] 02 9c }

  condition:
    any of them
}