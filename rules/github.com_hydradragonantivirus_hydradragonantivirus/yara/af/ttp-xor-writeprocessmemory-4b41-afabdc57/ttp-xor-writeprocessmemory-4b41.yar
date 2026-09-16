rule TTP_XOR_WriteProcessMemory_4b41 {
  strings:
    $key_4b41 = { 1c 33 [2] 2e 11 [2] 28 24 [2] 06 24 [2] 39 38 }

  condition:
    any of them
}