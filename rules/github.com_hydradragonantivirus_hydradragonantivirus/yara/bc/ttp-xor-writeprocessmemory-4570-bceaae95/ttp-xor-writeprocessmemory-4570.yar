rule TTP_XOR_WriteProcessMemory_4570 {
  strings:
    $key_4570 = { 12 02 [2] 20 20 [2] 26 15 [2] 08 15 [2] 37 09 }

  condition:
    any of them
}