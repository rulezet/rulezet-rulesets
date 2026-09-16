rule TTP_XOR_WriteProcessMemory_7819 {
  strings:
    $key_7819 = { 2f 6b [2] 1d 49 [2] 1b 7c [2] 35 7c [2] 0a 60 }

  condition:
    any of them
}