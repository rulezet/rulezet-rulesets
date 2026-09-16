rule TTP_XOR_WriteProcessMemory_1709 {
  strings:
    $key_1709 = { 40 7b [2] 72 59 [2] 74 6c [2] 5a 6c [2] 65 70 }

  condition:
    any of them
}