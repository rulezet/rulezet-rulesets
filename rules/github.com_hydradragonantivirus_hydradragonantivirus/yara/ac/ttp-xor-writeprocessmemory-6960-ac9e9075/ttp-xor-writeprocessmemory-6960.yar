rule TTP_XOR_WriteProcessMemory_6960 {
  strings:
    $key_6960 = { 3e 12 [2] 0c 30 [2] 0a 05 [2] 24 05 [2] 1b 19 }

  condition:
    any of them
}