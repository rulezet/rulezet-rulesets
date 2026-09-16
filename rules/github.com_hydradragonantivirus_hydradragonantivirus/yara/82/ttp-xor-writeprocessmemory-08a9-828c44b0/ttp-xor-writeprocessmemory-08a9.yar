rule TTP_XOR_WriteProcessMemory_08a9 {
  strings:
    $key_08a9 = { 5f db [2] 6d f9 [2] 6b cc [2] 45 cc [2] 7a d0 }

  condition:
    any of them
}