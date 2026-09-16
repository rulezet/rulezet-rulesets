rule TTP_XOR_WriteProcessMemory_ce17 {
  strings:
    $key_ce17 = { 99 65 [2] ab 47 [2] ad 72 [2] 83 72 [2] bc 6e }

  condition:
    any of them
}