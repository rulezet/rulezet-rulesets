rule TTP_XOR_WriteProcessMemory_3f75 {
  strings:
    $key_3f75 = { 68 07 [2] 5a 25 [2] 5c 10 [2] 72 10 [2] 4d 0c }

  condition:
    any of them
}