rule TTP_XOR_WriteProcessMemory_13f9 {
  strings:
    $key_13f9 = { 44 8b [2] 76 a9 [2] 70 9c [2] 5e 9c [2] 61 80 }

  condition:
    any of them
}