rule TTP_XOR_WriteProcessMemory_0974 {
  strings:
    $key_0974 = { 5e 06 [2] 6c 24 [2] 6a 11 [2] 44 11 [2] 7b 0d }

  condition:
    any of them
}