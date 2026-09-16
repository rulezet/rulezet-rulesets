rule TTP_XOR_WriteProcessMemory_6b42 {
  strings:
    $key_6b42 = { 3c 30 [2] 0e 12 [2] 08 27 [2] 26 27 [2] 19 3b }

  condition:
    any of them
}