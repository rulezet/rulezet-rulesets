rule TTP_XOR_WriteProcessMemory_7511 {
  strings:
    $key_7511 = { 22 63 [2] 10 41 [2] 16 74 [2] 38 74 [2] 07 68 }

  condition:
    any of them
}