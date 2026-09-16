rule TTP_XOR_WriteProcessMemory_7f67 {
  strings:
    $key_7f67 = { 28 15 [2] 1a 37 [2] 1c 02 [2] 32 02 [2] 0d 1e }

  condition:
    any of them
}