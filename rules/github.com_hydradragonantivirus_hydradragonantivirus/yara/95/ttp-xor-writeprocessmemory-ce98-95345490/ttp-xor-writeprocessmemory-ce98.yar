rule TTP_XOR_WriteProcessMemory_ce98 {
  strings:
    $key_ce98 = { 99 ea [2] ab c8 [2] ad fd [2] 83 fd [2] bc e1 }

  condition:
    any of them
}