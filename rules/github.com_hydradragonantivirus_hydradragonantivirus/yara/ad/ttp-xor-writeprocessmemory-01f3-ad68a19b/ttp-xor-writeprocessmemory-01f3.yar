rule TTP_XOR_WriteProcessMemory_01f3 {
  strings:
    $key_01f3 = { 56 81 [2] 64 a3 [2] 62 96 [2] 4c 96 [2] 73 8a }

  condition:
    any of them
}