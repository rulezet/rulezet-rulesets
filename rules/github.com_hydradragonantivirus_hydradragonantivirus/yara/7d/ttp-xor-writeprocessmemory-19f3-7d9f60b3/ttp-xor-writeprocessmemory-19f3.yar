rule TTP_XOR_WriteProcessMemory_19f3 {
  strings:
    $key_19f3 = { 4e 81 [2] 7c a3 [2] 7a 96 [2] 54 96 [2] 6b 8a }

  condition:
    any of them
}