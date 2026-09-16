rule TTP_XOR_WriteProcessMemory_ce03 {
  strings:
    $key_ce03 = { 99 71 [2] ab 53 [2] ad 66 [2] 83 66 [2] bc 7a }

  condition:
    any of them
}