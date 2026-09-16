rule TTP_XOR_WriteProcessMemory_2fe9 {
  strings:
    $key_2fe9 = { 78 9b [2] 4a b9 [2] 4c 8c [2] 62 8c [2] 5d 90 }

  condition:
    any of them
}