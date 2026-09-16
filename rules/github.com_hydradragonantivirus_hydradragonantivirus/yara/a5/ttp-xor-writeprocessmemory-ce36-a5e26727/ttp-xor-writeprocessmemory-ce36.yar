rule TTP_XOR_WriteProcessMemory_ce36 {
  strings:
    $key_ce36 = { 99 44 [2] ab 66 [2] ad 53 [2] 83 53 [2] bc 4f }

  condition:
    any of them
}