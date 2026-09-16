rule TTP_XOR_WriteProcessMemory_3bd3 {
  strings:
    $key_3bd3 = { 6c a1 [2] 5e 83 [2] 58 b6 [2] 76 b6 [2] 49 aa }

  condition:
    any of them
}