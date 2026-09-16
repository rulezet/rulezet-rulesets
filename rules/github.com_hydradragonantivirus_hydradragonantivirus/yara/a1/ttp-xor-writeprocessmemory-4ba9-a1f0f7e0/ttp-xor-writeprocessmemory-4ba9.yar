rule TTP_XOR_WriteProcessMemory_4ba9 {
  strings:
    $key_4ba9 = { 1c db [2] 2e f9 [2] 28 cc [2] 06 cc [2] 39 d0 }

  condition:
    any of them
}