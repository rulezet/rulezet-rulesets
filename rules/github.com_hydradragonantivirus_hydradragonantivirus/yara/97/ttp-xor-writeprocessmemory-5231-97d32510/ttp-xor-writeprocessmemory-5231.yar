rule TTP_XOR_WriteProcessMemory_5231 {
  strings:
    $key_5231 = { 05 43 [2] 37 61 [2] 31 54 [2] 1f 54 [2] 20 48 }

  condition:
    any of them
}