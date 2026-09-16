rule TTP_XOR_WriteProcessMemory_7660 {
  strings:
    $key_7660 = { 21 12 [2] 13 30 [2] 15 05 [2] 3b 05 [2] 04 19 }

  condition:
    any of them
}