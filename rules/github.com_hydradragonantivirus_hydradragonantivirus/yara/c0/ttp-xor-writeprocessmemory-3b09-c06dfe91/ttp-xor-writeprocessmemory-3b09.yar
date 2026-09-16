rule TTP_XOR_WriteProcessMemory_3b09 {
  strings:
    $key_3b09 = { 6c 7b [2] 5e 59 [2] 58 6c [2] 76 6c [2] 49 70 }

  condition:
    any of them
}