rule TTP_XOR_WriteProcessMemory_62e5 {
  strings:
    $key_62e5 = { 35 97 [2] 07 b5 [2] 01 80 [2] 2f 80 [2] 10 9c }

  condition:
    any of them
}