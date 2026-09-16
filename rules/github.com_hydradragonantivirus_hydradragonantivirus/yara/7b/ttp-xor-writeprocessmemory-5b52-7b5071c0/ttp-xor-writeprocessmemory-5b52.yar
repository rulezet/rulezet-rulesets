rule TTP_XOR_WriteProcessMemory_5b52 {
  strings:
    $key_5b52 = { 0c 20 [2] 3e 02 [2] 38 37 [2] 16 37 [2] 29 2b }

  condition:
    any of them
}