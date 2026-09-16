rule TTP_XOR_WriteProcessMemory_ce06 {
  strings:
    $key_ce06 = { 99 74 [2] ab 56 [2] ad 63 [2] 83 63 [2] bc 7f }

  condition:
    any of them
}