rule TTP_XOR_WriteProcessMemory_1731 {
  strings:
    $key_1731 = { 40 43 [2] 72 61 [2] 74 54 [2] 5a 54 [2] 65 48 }

  condition:
    any of them
}