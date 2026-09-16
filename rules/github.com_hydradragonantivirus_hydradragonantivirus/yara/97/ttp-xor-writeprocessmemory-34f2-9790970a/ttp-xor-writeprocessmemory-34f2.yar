rule TTP_XOR_WriteProcessMemory_34f2 {
  strings:
    $key_34f2 = { 63 80 [2] 51 a2 [2] 57 97 [2] 79 97 [2] 46 8b }

  condition:
    any of them
}