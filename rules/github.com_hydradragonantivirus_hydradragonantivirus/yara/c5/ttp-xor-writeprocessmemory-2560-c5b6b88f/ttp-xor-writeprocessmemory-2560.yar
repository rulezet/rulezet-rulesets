rule TTP_XOR_WriteProcessMemory_2560 {
  strings:
    $key_2560 = { 72 12 [2] 40 30 [2] 46 05 [2] 68 05 [2] 57 19 }

  condition:
    any of them
}