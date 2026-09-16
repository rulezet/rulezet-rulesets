rule TTP_XOR_WriteProcessMemory_24f2 {
  strings:
    $key_24f2 = { 73 80 [2] 41 a2 [2] 47 97 [2] 69 97 [2] 56 8b }

  condition:
    any of them
}