rule TTP_XOR_WriteProcessMemory_5b67 {
  strings:
    $key_5b67 = { 0c 15 [2] 3e 37 [2] 38 02 [2] 16 02 [2] 29 1e }

  condition:
    any of them
}