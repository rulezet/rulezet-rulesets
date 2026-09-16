rule TTP_XOR_WriteProcessMemory_4731 {
  strings:
    $key_4731 = { 10 43 [2] 22 61 [2] 24 54 [2] 0a 54 [2] 35 48 }

  condition:
    any of them
}