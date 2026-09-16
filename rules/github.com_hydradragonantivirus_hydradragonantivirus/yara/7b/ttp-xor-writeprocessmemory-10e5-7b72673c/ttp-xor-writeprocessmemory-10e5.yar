rule TTP_XOR_WriteProcessMemory_10e5 {
  strings:
    $key_10e5 = { 47 97 [2] 75 b5 [2] 73 80 [2] 5d 80 [2] 62 9c }

  condition:
    any of them
}