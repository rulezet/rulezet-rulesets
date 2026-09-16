rule TTP_XOR_WriteProcessMemory_28f3 {
  strings:
    $key_28f3 = { 7f 81 [2] 4d a3 [2] 4b 96 [2] 65 96 [2] 5a 8a }

  condition:
    any of them
}