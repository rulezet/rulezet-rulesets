rule TTP_XOR_WriteProcessMemory_3211 {
  strings:
    $key_3211 = { 65 63 [2] 57 41 [2] 51 74 [2] 7f 74 [2] 40 68 }

  condition:
    any of them
}