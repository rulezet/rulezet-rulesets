rule TTP_XOR_WriteProcessMemory_5169 {
  strings:
    $key_5169 = { 06 1b [2] 34 39 [2] 32 0c [2] 1c 0c [2] 23 10 }

  condition:
    any of them
}