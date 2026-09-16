rule TTP_XOR_WriteProcessMemory_1b73 {
  strings:
    $key_1b73 = { 4c 01 [2] 7e 23 [2] 78 16 [2] 56 16 [2] 69 0a }

  condition:
    any of them
}