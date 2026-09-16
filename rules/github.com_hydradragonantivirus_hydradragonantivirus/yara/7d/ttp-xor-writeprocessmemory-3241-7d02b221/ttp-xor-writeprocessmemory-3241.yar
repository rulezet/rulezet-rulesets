rule TTP_XOR_WriteProcessMemory_3241 {
  strings:
    $key_3241 = { 65 33 [2] 57 11 [2] 51 24 [2] 7f 24 [2] 40 38 }

  condition:
    any of them
}