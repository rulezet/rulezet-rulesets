rule TTP_XOR_WriteProcessMemory_09f2 {
  strings:
    $key_09f2 = { 5e 80 [2] 6c a2 [2] 6a 97 [2] 44 97 [2] 7b 8b }

  condition:
    any of them
}