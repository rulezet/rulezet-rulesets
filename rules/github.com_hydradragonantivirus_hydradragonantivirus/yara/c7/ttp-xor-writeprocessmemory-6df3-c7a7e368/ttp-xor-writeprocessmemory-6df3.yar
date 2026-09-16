rule TTP_XOR_WriteProcessMemory_6df3 {
  strings:
    $key_6df3 = { 3a 81 [2] 08 a3 [2] 0e 96 [2] 20 96 [2] 1f 8a }

  condition:
    any of them
}