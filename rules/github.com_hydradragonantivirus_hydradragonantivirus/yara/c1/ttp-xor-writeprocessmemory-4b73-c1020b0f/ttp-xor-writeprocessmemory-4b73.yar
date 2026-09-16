rule TTP_XOR_WriteProcessMemory_4b73 {
  strings:
    $key_4b73 = { 1c 01 [2] 2e 23 [2] 28 16 [2] 06 16 [2] 39 0a }

  condition:
    any of them
}