rule TTP_XOR_WriteProcessMemory_29f3 {
  strings:
    $key_29f3 = { 7e 81 [2] 4c a3 [2] 4a 96 [2] 64 96 [2] 5b 8a }

  condition:
    any of them
}