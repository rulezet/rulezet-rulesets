rule TTP_XOR_WriteProcessMemory_3570 {
  strings:
    $key_3570 = { 62 02 [2] 50 20 [2] 56 15 [2] 78 15 [2] 47 09 }

  condition:
    any of them
}