rule TTP_XOR_WriteProcessMemory_5270 {
  strings:
    $key_5270 = { 05 02 [2] 37 20 [2] 31 15 [2] 1f 15 [2] 20 09 }

  condition:
    any of them
}