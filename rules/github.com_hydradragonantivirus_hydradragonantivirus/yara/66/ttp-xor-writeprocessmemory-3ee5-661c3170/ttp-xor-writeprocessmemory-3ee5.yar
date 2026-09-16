rule TTP_XOR_WriteProcessMemory_3ee5 {
  strings:
    $key_3ee5 = { 69 97 [2] 5b b5 [2] 5d 80 [2] 73 80 [2] 4c 9c }

  condition:
    any of them
}