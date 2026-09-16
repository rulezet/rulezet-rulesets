rule TTP_XOR_WriteProcessMemory_72e5 {
  strings:
    $key_72e5 = { 25 97 [2] 17 b5 [2] 11 80 [2] 3f 80 [2] 00 9c }

  condition:
    any of them
}