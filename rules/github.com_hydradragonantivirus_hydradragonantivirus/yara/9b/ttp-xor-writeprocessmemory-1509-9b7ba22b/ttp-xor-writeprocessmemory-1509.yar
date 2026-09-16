rule TTP_XOR_WriteProcessMemory_1509 {
  strings:
    $key_1509 = { 42 7b [2] 70 59 [2] 76 6c [2] 58 6c [2] 67 70 }

  condition:
    any of them
}