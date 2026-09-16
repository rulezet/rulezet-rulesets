rule TTP_XOR_WriteProcessMemory_5ba9 {
  strings:
    $key_5ba9 = { 0c db [2] 3e f9 [2] 38 cc [2] 16 cc [2] 29 d0 }

  condition:
    any of them
}