rule TTP_XOR_WriteProcessMemory_3b52 {
  strings:
    $key_3b52 = { 6c 20 [2] 5e 02 [2] 58 37 [2] 76 37 [2] 49 2b }

  condition:
    any of them
}