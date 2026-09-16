rule TTP_XOR_WriteProcessMemory_36f3 {
  strings:
    $key_36f3 = { 61 81 [2] 53 a3 [2] 55 96 [2] 7b 96 [2] 44 8a }

  condition:
    any of them
}