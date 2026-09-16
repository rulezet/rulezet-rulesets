rule TTP_XOR_WriteProcessMemory_0645 {
  strings:
    $key_0645 = { 51 37 [2] 63 15 [2] 65 20 [2] 4b 20 [2] 74 3c }

  condition:
    any of them
}