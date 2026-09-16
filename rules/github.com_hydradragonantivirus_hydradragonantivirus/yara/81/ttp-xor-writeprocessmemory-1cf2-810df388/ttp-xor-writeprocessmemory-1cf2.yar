rule TTP_XOR_WriteProcessMemory_1cf2 {
  strings:
    $key_1cf2 = { 4b 80 [2] 79 a2 [2] 7f 97 [2] 51 97 [2] 6e 8b }

  condition:
    any of them
}