rule TTP_XOR_WriteProcessMemory_3b67 {
  strings:
    $key_3b67 = { 6c 15 [2] 5e 37 [2] 58 02 [2] 76 02 [2] 49 1e }

  condition:
    any of them
}