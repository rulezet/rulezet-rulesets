rule TTP_XOR_WriteProcessMemory_ce33 {
  strings:
    $key_ce33 = { 99 41 [2] ab 63 [2] ad 56 [2] 83 56 [2] bc 4a }

  condition:
    any of them
}