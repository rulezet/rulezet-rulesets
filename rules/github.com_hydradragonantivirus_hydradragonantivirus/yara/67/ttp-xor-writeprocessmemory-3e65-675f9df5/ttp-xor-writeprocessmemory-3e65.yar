rule TTP_XOR_WriteProcessMemory_3e65 {
  strings:
    $key_3e65 = { 69 17 [2] 5b 35 [2] 5d 00 [2] 73 00 [2] 4c 1c }

  condition:
    any of them
}