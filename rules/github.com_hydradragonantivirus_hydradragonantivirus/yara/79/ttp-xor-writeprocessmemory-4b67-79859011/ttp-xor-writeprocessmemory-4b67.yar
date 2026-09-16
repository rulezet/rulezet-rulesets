rule TTP_XOR_WriteProcessMemory_4b67 {
  strings:
    $key_4b67 = { 1c 15 [2] 2e 37 [2] 28 02 [2] 06 02 [2] 39 1e }

  condition:
    any of them
}