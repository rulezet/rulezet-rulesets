rule TTP_XOR_WriteProcessMemory_3e75 {
  strings:
    $key_3e75 = { 69 07 [2] 5b 25 [2] 5d 10 [2] 73 10 [2] 4c 0c }

  condition:
    any of them
}