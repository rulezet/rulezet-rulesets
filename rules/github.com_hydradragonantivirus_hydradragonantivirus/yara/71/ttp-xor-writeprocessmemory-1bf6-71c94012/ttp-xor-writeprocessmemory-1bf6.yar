rule TTP_XOR_WriteProcessMemory_1bf6 {
  strings:
    $key_1bf6 = { 4c 84 [2] 7e a6 [2] 78 93 [2] 56 93 [2] 69 8f }

  condition:
    any of them
}