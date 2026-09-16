rule TTP_XOR_WriteProcessMemory_4331 {
  strings:
    $key_4331 = { 14 43 [2] 26 61 [2] 20 54 [2] 0e 54 [2] 31 48 }

  condition:
    any of them
}