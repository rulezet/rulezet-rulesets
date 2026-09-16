rule TTP_XOR_WriteProcessMemory_6b52 {
  strings:
    $key_6b52 = { 3c 20 [2] 0e 02 [2] 08 37 [2] 26 37 [2] 19 2b }

  condition:
    any of them
}