rule TTP_XOR_WriteProcessMemory_14e9 {
  strings:
    $key_14e9 = { 43 9b [2] 71 b9 [2] 77 8c [2] 59 8c [2] 66 90 }

  condition:
    any of them
}