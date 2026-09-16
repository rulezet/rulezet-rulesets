rule TTP_XOR_WriteProcessMemory_1270 {
  strings:
    $key_1270 = { 45 02 [2] 77 20 [2] 71 15 [2] 5f 15 [2] 60 09 }

  condition:
    any of them
}