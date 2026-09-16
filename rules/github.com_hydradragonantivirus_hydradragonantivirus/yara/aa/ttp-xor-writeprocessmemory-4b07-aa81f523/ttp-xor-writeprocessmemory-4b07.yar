rule TTP_XOR_WriteProcessMemory_4b07 {
  strings:
    $key_4b07 = { 1c 75 [2] 2e 57 [2] 28 62 [2] 06 62 [2] 39 7e }

  condition:
    any of them
}