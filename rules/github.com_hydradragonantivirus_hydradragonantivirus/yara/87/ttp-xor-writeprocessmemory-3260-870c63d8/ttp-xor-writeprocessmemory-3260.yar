rule TTP_XOR_WriteProcessMemory_3260 {
  strings:
    $key_3260 = { 65 12 [2] 57 30 [2] 51 05 [2] 7f 05 [2] 40 19 }

  condition:
    any of them
}