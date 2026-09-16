rule TTP_XOR_WriteProcessMemory_3bf2 {
  strings:
    $key_3bf2 = { 6c 80 [2] 5e a2 [2] 58 97 [2] 76 97 [2] 49 8b }

  condition:
    any of them
}