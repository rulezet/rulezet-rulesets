rule TTP_XOR_WriteProcessMemory_5660 {
  strings:
    $key_5660 = { 01 12 [2] 33 30 [2] 35 05 [2] 1b 05 [2] 24 19 }

  condition:
    any of them
}