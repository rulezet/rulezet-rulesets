rule TTP_XOR_WriteProcessMemory_ce52 {
  strings:
    $key_ce52 = { 99 20 [2] ab 02 [2] ad 37 [2] 83 37 [2] bc 2b }

  condition:
    any of them
}