rule TTP_XOR_WriteProcessMemory_ce54 {
  strings:
    $key_ce54 = { 99 26 [2] ab 04 [2] ad 31 [2] 83 31 [2] bc 2d }

  condition:
    any of them
}