rule TTP_XOR_WriteProcessMemory_6b10 {
  strings:
    $key_6b10 = { 3c 62 [2] 0e 40 [2] 08 75 [2] 26 75 [2] 19 69 }

  condition:
    any of them
}