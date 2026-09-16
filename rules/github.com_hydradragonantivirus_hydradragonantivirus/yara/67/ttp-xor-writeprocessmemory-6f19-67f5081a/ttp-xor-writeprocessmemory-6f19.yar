rule TTP_XOR_WriteProcessMemory_6f19 {
  strings:
    $key_6f19 = { 38 6b [2] 0a 49 [2] 0c 7c [2] 22 7c [2] 1d 60 }

  condition:
    any of them
}