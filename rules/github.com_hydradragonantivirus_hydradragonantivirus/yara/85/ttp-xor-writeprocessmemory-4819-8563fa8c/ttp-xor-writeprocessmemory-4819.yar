rule TTP_XOR_WriteProcessMemory_4819 {
  strings:
    $key_4819 = { 1f 6b [2] 2d 49 [2] 2b 7c [2] 05 7c [2] 3a 60 }

  condition:
    any of them
}