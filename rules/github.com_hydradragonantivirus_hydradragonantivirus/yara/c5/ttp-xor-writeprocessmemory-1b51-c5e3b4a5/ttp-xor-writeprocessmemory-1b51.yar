rule TTP_XOR_WriteProcessMemory_1b51 {
  strings:
    $key_1b51 = { 4c 23 [2] 7e 01 [2] 78 34 [2] 56 34 [2] 69 28 }

  condition:
    any of them
}