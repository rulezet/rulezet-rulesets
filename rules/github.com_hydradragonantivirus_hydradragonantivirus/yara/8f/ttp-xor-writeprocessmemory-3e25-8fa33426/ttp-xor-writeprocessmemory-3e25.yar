rule TTP_XOR_WriteProcessMemory_3e25 {
  strings:
    $key_3e25 = { 69 57 [2] 5b 75 [2] 5d 40 [2] 73 40 [2] 4c 5c }

  condition:
    any of them
}