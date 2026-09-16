rule TTP_XOR_WriteProcessMemory_6b67 {
  strings:
    $key_6b67 = { 3c 15 [2] 0e 37 [2] 08 02 [2] 26 02 [2] 19 1e }

  condition:
    any of them
}