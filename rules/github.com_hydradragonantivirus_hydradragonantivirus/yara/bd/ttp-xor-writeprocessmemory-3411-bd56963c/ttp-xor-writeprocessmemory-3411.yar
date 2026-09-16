rule TTP_XOR_WriteProcessMemory_3411 {
  strings:
    $key_3411 = { 63 63 [2] 51 41 [2] 57 74 [2] 79 74 [2] 46 68 }

  condition:
    any of them
}