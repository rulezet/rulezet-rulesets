rule TTP_XOR_WriteProcessMemory_66f2 {
  strings:
    $key_66f2 = { 31 80 [2] 03 a2 [2] 05 97 [2] 2b 97 [2] 14 8b }

  condition:
    any of them
}