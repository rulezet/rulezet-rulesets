rule TTP_XOR_WriteProcessMemory_02f3 {
  strings:
    $key_02f3 = { 55 81 [2] 67 a3 [2] 61 96 [2] 4f 96 [2] 70 8a }

  condition:
    any of them
}