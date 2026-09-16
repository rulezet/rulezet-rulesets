rule TTP_XOR_WriteProcessMemory_2f65 {
  strings:
    $key_2f65 = { 78 17 [2] 4a 35 [2] 4c 00 [2] 62 00 [2] 5d 1c }

  condition:
    any of them
}