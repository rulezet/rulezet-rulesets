rule TTP_XOR_WriteProcessMemory_7319 {
  strings:
    $key_7319 = { 24 6b [2] 16 49 [2] 10 7c [2] 3e 7c [2] 01 60 }

  condition:
    any of them
}