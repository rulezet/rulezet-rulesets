rule TTP_XOR_WriteProcessMemory_7419 {
  strings:
    $key_7419 = { 23 6b [2] 11 49 [2] 17 7c [2] 39 7c [2] 06 60 }

  condition:
    any of them
}