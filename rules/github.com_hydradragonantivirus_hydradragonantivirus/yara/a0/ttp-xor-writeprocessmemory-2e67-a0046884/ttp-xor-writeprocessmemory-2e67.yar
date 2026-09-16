rule TTP_XOR_WriteProcessMemory_2e67 {
  strings:
    $key_2e67 = { 79 15 [2] 4b 37 [2] 4d 02 [2] 63 02 [2] 5c 1e }

  condition:
    any of them
}