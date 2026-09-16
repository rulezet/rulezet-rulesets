rule TTP_XOR_WriteProcessMemory_0650 {
  strings:
    $key_0650 = { 51 22 [2] 63 00 [2] 65 35 [2] 4b 35 [2] 74 29 }

  condition:
    any of them
}