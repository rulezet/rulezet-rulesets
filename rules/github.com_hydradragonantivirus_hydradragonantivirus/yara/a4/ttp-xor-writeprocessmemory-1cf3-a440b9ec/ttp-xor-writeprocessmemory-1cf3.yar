rule TTP_XOR_WriteProcessMemory_1cf3 {
  strings:
    $key_1cf3 = { 4b 81 [2] 79 a3 [2] 7f 96 [2] 51 96 [2] 6e 8a }

  condition:
    any of them
}