rule TTP_XOR_WriteProcessMemory_7709 {
  strings:
    $key_7709 = { 20 7b [2] 12 59 [2] 14 6c [2] 3a 6c [2] 05 70 }

  condition:
    any of them
}