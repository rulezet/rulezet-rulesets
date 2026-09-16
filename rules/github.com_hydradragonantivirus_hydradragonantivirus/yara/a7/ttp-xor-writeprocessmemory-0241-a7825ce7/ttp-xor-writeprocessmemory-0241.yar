rule TTP_XOR_WriteProcessMemory_0241 {
  strings:
    $key_0241 = { 55 33 [2] 67 11 [2] 61 24 [2] 4f 24 [2] 70 38 }

  condition:
    any of them
}