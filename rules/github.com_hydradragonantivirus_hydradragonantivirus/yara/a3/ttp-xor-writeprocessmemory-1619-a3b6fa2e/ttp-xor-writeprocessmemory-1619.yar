rule TTP_XOR_WriteProcessMemory_1619 {
  strings:
    $key_1619 = { 41 6b [2] 73 49 [2] 75 7c [2] 5b 7c [2] 64 60 }

  condition:
    any of them
}