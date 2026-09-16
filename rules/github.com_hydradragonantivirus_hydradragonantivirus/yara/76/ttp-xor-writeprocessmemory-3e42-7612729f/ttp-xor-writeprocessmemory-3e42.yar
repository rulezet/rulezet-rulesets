rule TTP_XOR_WriteProcessMemory_3e42 {
  strings:
    $key_3e42 = { 69 30 [2] 5b 12 [2] 5d 27 [2] 73 27 [2] 4c 3b }

  condition:
    any of them
}