rule TTP_XOR_WriteProcessMemory_0bd3 {
  strings:
    $key_0bd3 = { 5c a1 [2] 6e 83 [2] 68 b6 [2] 46 b6 [2] 79 aa }

  condition:
    any of them
}