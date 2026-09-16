rule TTP_XOR_WriteProcessMemory_6731 {
  strings:
    $key_6731 = { 30 43 [2] 02 61 [2] 04 54 [2] 2a 54 [2] 15 48 }

  condition:
    any of them
}