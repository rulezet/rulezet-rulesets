rule TTP_XOR_WriteProcessMemory_5431 {
  strings:
    $key_5431 = { 03 43 [2] 31 61 [2] 37 54 [2] 19 54 [2] 26 48 }

  condition:
    any of them
}