rule TTP_XOR_WriteProcessMemory_1e67 {
  strings:
    $key_1e67 = { 49 15 [2] 7b 37 [2] 7d 02 [2] 53 02 [2] 6c 1e }

  condition:
    any of them
}