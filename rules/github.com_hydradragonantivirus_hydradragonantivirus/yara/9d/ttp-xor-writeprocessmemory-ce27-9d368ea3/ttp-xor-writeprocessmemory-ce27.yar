rule TTP_XOR_WriteProcessMemory_ce27 {
  strings:
    $key_ce27 = { 99 55 [2] ab 77 [2] ad 42 [2] 83 42 [2] bc 5e }

  condition:
    any of them
}