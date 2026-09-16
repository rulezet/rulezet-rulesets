rule TTP_XOR_WriteProcessMemory_4b42 {
  strings:
    $key_4b42 = { 1c 30 [2] 2e 12 [2] 28 27 [2] 06 27 [2] 39 3b }

  condition:
    any of them
}