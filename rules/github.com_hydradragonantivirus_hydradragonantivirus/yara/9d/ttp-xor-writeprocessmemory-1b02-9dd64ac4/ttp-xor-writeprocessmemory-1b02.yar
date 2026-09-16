rule TTP_XOR_WriteProcessMemory_1b02 {
  strings:
    $key_1b02 = { 4c 70 [2] 7e 52 [2] 78 67 [2] 56 67 [2] 69 7b }

  condition:
    any of them
}