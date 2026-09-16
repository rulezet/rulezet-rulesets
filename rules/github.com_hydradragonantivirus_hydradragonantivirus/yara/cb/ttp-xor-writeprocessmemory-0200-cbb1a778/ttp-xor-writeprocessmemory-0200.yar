rule TTP_XOR_WriteProcessMemory_0200 {
  strings:
    $key_0200 = { 55 72 [2] 67 50 [2] 61 65 [2] 4f 65 [2] 70 79 }

  condition:
    any of them
}