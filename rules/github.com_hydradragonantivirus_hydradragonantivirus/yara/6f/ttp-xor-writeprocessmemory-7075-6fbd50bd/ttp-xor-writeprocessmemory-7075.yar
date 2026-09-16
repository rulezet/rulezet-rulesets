rule TTP_XOR_WriteProcessMemory_7075 {
  strings:
    $key_7075 = { 27 07 [2] 15 25 [2] 13 10 [2] 3d 10 [2] 02 0c }

  condition:
    any of them
}