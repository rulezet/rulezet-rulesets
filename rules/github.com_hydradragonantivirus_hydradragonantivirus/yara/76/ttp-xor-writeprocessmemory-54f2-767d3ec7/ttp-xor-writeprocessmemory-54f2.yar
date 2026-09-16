rule TTP_XOR_WriteProcessMemory_54f2 {
  strings:
    $key_54f2 = { 03 80 [2] 31 a2 [2] 37 97 [2] 19 97 [2] 26 8b }

  condition:
    any of them
}