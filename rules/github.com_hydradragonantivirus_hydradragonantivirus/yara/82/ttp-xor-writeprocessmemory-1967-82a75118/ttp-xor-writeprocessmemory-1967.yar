rule TTP_XOR_WriteProcessMemory_1967 {
  strings:
    $key_1967 = { 4e 15 [2] 7c 37 [2] 7a 02 [2] 54 02 [2] 6b 1e }

  condition:
    any of them
}