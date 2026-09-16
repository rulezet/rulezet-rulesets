rule TTP_XOR_WriteProcessMemory_2709 {
  strings:
    $key_2709 = { 70 7b [2] 42 59 [2] 44 6c [2] 6a 6c [2] 55 70 }

  condition:
    any of them
}