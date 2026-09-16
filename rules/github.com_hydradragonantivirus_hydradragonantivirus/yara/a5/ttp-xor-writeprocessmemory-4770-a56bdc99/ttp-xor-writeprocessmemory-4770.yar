rule TTP_XOR_WriteProcessMemory_4770 {
  strings:
    $key_4770 = { 10 02 [2] 22 20 [2] 24 15 [2] 0a 15 [2] 35 09 }

  condition:
    any of them
}