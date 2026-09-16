rule TTP_XOR_WriteProcessMemory_1bf3 {
  strings:
    $key_1bf3 = { 4c 81 [2] 7e a3 [2] 78 96 [2] 56 96 [2] 69 8a }

  condition:
    any of them
}