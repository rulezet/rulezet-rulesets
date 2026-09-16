rule TTP_XOR_WriteProcessMemory_0070 {
  strings:
    $key_0070 = { 57 02 [2] 65 20 [2] 63 15 [2] 4d 15 [2] 72 09 }

  condition:
    any of them
}