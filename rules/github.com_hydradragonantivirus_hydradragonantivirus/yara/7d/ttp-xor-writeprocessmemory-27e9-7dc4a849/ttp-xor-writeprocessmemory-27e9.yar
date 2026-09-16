rule TTP_XOR_WriteProcessMemory_27e9 {
  strings:
    $key_27e9 = { 70 9b [2] 42 b9 [2] 44 8c [2] 6a 8c [2] 55 90 }

  condition:
    any of them
}