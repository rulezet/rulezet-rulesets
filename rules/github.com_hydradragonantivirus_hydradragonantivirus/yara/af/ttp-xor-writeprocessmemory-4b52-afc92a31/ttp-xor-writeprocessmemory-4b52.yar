rule TTP_XOR_WriteProcessMemory_4b52 {
  strings:
    $key_4b52 = { 1c 20 [2] 2e 02 [2] 28 37 [2] 06 37 [2] 39 2b }

  condition:
    any of them
}