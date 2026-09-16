rule TTP_XOR_WriteProcessMemory_ce47 {
  strings:
    $key_ce47 = { 99 35 [2] ab 17 [2] ad 22 [2] 83 22 [2] bc 3e }

  condition:
    any of them
}