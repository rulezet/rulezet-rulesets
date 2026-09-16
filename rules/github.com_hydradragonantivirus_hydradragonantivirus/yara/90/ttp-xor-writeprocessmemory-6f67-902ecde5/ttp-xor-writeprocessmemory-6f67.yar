rule TTP_XOR_WriteProcessMemory_6f67 {
  strings:
    $key_6f67 = { 38 15 [2] 0a 37 [2] 0c 02 [2] 22 02 [2] 1d 1e }

  condition:
    any of them
}