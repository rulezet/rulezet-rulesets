rule TTP_XOR_WriteProcessMemory_2f02 {
  strings:
    $key_2f02 = { 78 70 [2] 4a 52 [2] 4c 67 [2] 62 67 [2] 5d 7b }

  condition:
    any of them
}