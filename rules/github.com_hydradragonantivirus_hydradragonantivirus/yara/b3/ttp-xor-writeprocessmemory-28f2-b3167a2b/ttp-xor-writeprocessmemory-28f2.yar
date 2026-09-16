rule TTP_XOR_WriteProcessMemory_28f2 {
  strings:
    $key_28f2 = { 7f 80 [2] 4d a2 [2] 4b 97 [2] 65 97 [2] 5a 8b }

  condition:
    any of them
}