rule TTP_XOR_WriteProcessMemory_4b09 {
  strings:
    $key_4b09 = { 1c 7b [2] 2e 59 [2] 28 6c [2] 06 6c [2] 39 70 }

  condition:
    any of them
}