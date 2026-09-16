rule TTP_XOR_WriteProcessMemory_08f2 {
  strings:
    $key_08f2 = { 5f 80 [2] 6d a2 [2] 6b 97 [2] 45 97 [2] 7a 8b }

  condition:
    any of them
}