rule TTP_XOR_WriteProcessMemory_1f67 {
  strings:
    $key_1f67 = { 48 15 [2] 7a 37 [2] 7c 02 [2] 52 02 [2] 6d 1e }

  condition:
    any of them
}