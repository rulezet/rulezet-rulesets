rule TTP_XOR_WriteProcessMemory_1309 {
  strings:
    $key_1309 = { 44 7b [2] 76 59 [2] 70 6c [2] 5e 6c [2] 61 70 }

  condition:
    any of them
}