rule TTP_XOR_WriteProcessMemory_5261 {
  strings:
    $key_5261 = { 05 13 [2] 37 31 [2] 31 04 [2] 1f 04 [2] 20 18 }

  condition:
    any of them
}