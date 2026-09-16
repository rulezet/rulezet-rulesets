rule TTP_XOR_WriteProcessMemory_d8a9 {
  strings:
    $key_d8a9 = { 8f db [2] bd f9 [2] bb cc [2] 95 cc [2] aa d0 }

  condition:
    any of them
}