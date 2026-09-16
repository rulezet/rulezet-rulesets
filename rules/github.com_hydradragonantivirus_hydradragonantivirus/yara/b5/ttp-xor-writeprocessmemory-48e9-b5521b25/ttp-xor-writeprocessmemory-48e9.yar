rule TTP_XOR_WriteProcessMemory_48e9 {
  strings:
    $key_48e9 = { 1f 9b [2] 2d b9 [2] 2b 8c [2] 05 8c [2] 3a 90 }

  condition:
    any of them
}