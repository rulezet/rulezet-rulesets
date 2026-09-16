rule TTP_XOR_WriteProcessMemory_5cf2 {
  strings:
    $key_5cf2 = { 0b 80 [2] 39 a2 [2] 3f 97 [2] 11 97 [2] 2e 8b }

  condition:
    any of them
}