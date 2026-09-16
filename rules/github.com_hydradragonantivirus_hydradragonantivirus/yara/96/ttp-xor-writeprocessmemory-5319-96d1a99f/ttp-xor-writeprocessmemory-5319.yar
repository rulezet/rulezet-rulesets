rule TTP_XOR_WriteProcessMemory_5319 {
  strings:
    $key_5319 = { 04 6b [2] 36 49 [2] 30 7c [2] 1e 7c [2] 21 60 }

  condition:
    any of them
}