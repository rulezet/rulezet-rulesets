rule TTP_XOR_WriteProcessMemory_33e9 {
  strings:
    $key_33e9 = { 64 9b [2] 56 b9 [2] 50 8c [2] 7e 8c [2] 41 90 }

  condition:
    any of them
}