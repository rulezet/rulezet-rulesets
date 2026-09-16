rule TTP_XOR_WriteProcessMemory_3431 {
  strings:
    $key_3431 = { 63 43 [2] 51 61 [2] 57 54 [2] 79 54 [2] 46 48 }

  condition:
    any of them
}