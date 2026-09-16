rule TTP_XOR_WriteProcessMemory_6729 {
  strings:
    $key_6729 = { 30 5b [2] 02 79 [2] 04 4c [2] 2a 4c [2] 15 50 }

  condition:
    any of them
}