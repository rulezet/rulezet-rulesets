rule TTP_XOR_WriteProcessMemory_61f2 {
  strings:
    $key_61f2 = { 36 80 [2] 04 a2 [2] 02 97 [2] 2c 97 [2] 13 8b }

  condition:
    any of them
}