rule TTP_XOR_WriteProcessMemory_6967 {
  strings:
    $key_6967 = { 3e 15 [2] 0c 37 [2] 0a 02 [2] 24 02 [2] 1b 1e }

  condition:
    any of them
}