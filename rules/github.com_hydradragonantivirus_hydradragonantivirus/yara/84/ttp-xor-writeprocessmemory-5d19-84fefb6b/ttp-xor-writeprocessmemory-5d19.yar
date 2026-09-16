rule TTP_XOR_WriteProcessMemory_5d19 {
  strings:
    $key_5d19 = { 0a 6b [2] 38 49 [2] 3e 7c [2] 10 7c [2] 2f 60 }

  condition:
    any of them
}