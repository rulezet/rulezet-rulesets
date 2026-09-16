rule TTP_XOR_WriteProcessMemory_1b09 {
  strings:
    $key_1b09 = { 4c 7b [2] 7e 59 [2] 78 6c [2] 56 6c [2] 69 70 }

  condition:
    any of them
}