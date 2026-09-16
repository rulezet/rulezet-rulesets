rule TTP_XOR_WriteProcessMemory_0570 {
  strings:
    $key_0570 = { 52 02 [2] 60 20 [2] 66 15 [2] 48 15 [2] 77 09 }

  condition:
    any of them
}