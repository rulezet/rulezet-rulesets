rule TTP_XOR_WriteProcessMemory_5569 {
  strings:
    $key_5569 = { 02 1b [2] 30 39 [2] 36 0c [2] 18 0c [2] 27 10 }

  condition:
    any of them
}