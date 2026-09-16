rule TTP_XOR_WriteProcessMemory_41f2 {
  strings:
    $key_41f2 = { 16 80 [2] 24 a2 [2] 22 97 [2] 0c 97 [2] 33 8b }

  condition:
    any of them
}