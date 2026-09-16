rule TTP_XOR_WriteProcessMemory_0250 {
  strings:
    $key_0250 = { 55 22 [2] 67 00 [2] 61 35 [2] 4f 35 [2] 70 29 }

  condition:
    any of them
}