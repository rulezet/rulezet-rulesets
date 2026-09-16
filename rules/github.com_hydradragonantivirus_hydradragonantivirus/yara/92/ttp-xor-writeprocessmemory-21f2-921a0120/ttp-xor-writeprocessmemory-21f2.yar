rule TTP_XOR_WriteProcessMemory_21f2 {
  strings:
    $key_21f2 = { 76 80 [2] 44 a2 [2] 42 97 [2] 6c 97 [2] 53 8b }

  condition:
    any of them
}