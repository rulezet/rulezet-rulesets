rule TTP_XOR_WriteProcessMemory_5b09 {
  strings:
    $key_5b09 = { 0c 7b [2] 3e 59 [2] 38 6c [2] 16 6c [2] 29 70 }

  condition:
    any of them
}