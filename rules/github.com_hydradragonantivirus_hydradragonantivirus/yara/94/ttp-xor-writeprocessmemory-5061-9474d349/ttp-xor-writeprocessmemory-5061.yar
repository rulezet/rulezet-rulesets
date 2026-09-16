rule TTP_XOR_WriteProcessMemory_5061 {
  strings:
    $key_5061 = { 07 13 [2] 35 31 [2] 33 04 [2] 1d 04 [2] 22 18 }

  condition:
    any of them
}