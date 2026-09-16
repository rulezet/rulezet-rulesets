rule TTP_XOR_WriteProcessMemory_ce96 {
  strings:
    $key_ce96 = { 99 e4 [2] ab c6 [2] ad f3 [2] 83 f3 [2] bc ef }

  condition:
    any of them
}