rule TTP_XOR_WriteProcessMemory_0ba9 {
  strings:
    $key_0ba9 = { 5c db [2] 6e f9 [2] 68 cc [2] 46 cc [2] 79 d0 }

  condition:
    any of them
}