rule TTP_XOR_WriteProcessMemory_7307 {
  strings:
    $key_7307 = { 24 75 [2] 16 57 [2] 10 62 [2] 3e 62 [2] 01 7e }

  condition:
    any of them
}