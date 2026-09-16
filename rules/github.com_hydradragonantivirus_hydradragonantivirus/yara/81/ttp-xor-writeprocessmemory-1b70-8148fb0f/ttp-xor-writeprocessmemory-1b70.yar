rule TTP_XOR_WriteProcessMemory_1b70 {
  strings:
    $key_1b70 = { 4c 02 [2] 7e 20 [2] 78 15 [2] 56 15 [2] 69 09 }

  condition:
    any of them
}