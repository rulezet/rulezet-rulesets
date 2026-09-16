rule TTP_XOR_WriteProcessMemory_4b70 {
  strings:
    $key_4b70 = { 1c 02 [2] 2e 20 [2] 28 15 [2] 06 15 [2] 39 09 }

  condition:
    any of them
}