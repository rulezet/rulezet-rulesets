rule TTP_XOR_WriteProcessMemory_7570 {
  strings:
    $key_7570 = { 22 02 [2] 10 20 [2] 16 15 [2] 38 15 [2] 07 09 }

  condition:
    any of them
}