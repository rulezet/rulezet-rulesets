rule TTP_XOR_WriteProcessMemory_6fe5 {
  strings:
    $key_6fe5 = { 38 97 [2] 0a b5 [2] 0c 80 [2] 22 80 [2] 1d 9c }

  condition:
    any of them
}