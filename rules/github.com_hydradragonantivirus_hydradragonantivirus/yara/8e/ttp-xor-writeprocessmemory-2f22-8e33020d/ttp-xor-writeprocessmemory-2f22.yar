rule TTP_XOR_WriteProcessMemory_2f22 {
  strings:
    $key_2f22 = { 78 50 [2] 4a 72 [2] 4c 47 [2] 62 47 [2] 5d 5b }

  condition:
    any of them
}