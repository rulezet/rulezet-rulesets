rule TTP_XOR_WriteProcessMemory_7e67 {
  strings:
    $key_7e67 = { 29 15 [2] 1b 37 [2] 1d 02 [2] 33 02 [2] 0c 1e }

  condition:
    any of them
}