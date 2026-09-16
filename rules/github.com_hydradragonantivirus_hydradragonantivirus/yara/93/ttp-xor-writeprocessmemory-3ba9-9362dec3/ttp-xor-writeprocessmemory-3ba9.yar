rule TTP_XOR_WriteProcessMemory_3ba9 {
  strings:
    $key_3ba9 = { 6c db [2] 5e f9 [2] 58 cc [2] 76 cc [2] 49 d0 }

  condition:
    any of them
}