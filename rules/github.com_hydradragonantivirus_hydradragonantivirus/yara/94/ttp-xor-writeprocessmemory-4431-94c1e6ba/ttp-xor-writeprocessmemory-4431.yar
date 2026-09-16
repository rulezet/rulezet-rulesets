rule TTP_XOR_WriteProcessMemory_4431 {
  strings:
    $key_4431 = { 13 43 [2] 21 61 [2] 27 54 [2] 09 54 [2] 36 48 }

  condition:
    any of them
}