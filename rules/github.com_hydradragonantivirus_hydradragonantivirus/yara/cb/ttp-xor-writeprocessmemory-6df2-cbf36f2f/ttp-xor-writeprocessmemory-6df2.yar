rule TTP_XOR_WriteProcessMemory_6df2 {
  strings:
    $key_6df2 = { 3a 80 [2] 08 a2 [2] 0e 97 [2] 20 97 [2] 1f 8b }

  condition:
    any of them
}