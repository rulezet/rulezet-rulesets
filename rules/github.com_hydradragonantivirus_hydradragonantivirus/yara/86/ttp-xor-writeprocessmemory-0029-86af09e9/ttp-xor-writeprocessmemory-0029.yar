rule TTP_XOR_WriteProcessMemory_0029 {
  strings:
    $key_0029 = { 57 5b [2] 65 79 [2] 63 4c [2] 4d 4c [2] 72 50 }

  condition:
    any of them
}