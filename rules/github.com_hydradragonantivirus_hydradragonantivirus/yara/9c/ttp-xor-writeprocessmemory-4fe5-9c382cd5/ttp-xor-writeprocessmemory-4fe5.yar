rule TTP_XOR_WriteProcessMemory_4fe5 {
  strings:
    $key_4fe5 = { 18 97 [2] 2a b5 [2] 2c 80 [2] 02 80 [2] 3d 9c }

  condition:
    any of them
}