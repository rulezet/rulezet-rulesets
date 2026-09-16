rule TTP_XOR_WriteProcessMemory_d8b5 {
  strings:
    $key_d8b5 = { 8f c7 [2] bd e5 [2] bb d0 [2] 95 d0 [2] aa cc }

  condition:
    any of them
}