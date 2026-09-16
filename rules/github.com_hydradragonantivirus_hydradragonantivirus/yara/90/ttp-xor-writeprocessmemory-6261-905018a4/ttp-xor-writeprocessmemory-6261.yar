rule TTP_XOR_WriteProcessMemory_6261 {
  strings:
    $key_6261 = { 35 13 [2] 07 31 [2] 01 04 [2] 2f 04 [2] 10 18 }

  condition:
    any of them
}