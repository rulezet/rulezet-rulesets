rule TTP_XOR_WriteProcessMemory_2f45 {
  strings:
    $key_2f45 = { 78 37 [2] 4a 15 [2] 4c 20 [2] 62 20 [2] 5d 3c }

  condition:
    any of them
}