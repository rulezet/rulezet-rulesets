rule TTP_XOR_WriteProcessMemory_36f2 {
  strings:
    $key_36f2 = { 61 80 [2] 53 a2 [2] 55 97 [2] 7b 97 [2] 44 8b }

  condition:
    any of them
}