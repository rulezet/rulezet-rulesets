rule TTP_XOR_WriteProcessMemory_48f9 {
  strings:
    $key_48f9 = { 1f 8b [2] 2d a9 [2] 2b 9c [2] 05 9c [2] 3a 80 }

  condition:
    any of them
}