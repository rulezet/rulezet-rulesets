rule TTP_XOR_WriteProcessMemory_1b52 {
  strings:
    $key_1b52 = { 4c 20 [2] 7e 02 [2] 78 37 [2] 56 37 [2] 69 2b }

  condition:
    any of them
}