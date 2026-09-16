rule TTP_XOR_WriteProcessMemory_4ee5 {
  strings:
    $key_4ee5 = { 19 97 [2] 2b b5 [2] 2d 80 [2] 03 80 [2] 3c 9c }

  condition:
    any of them
}