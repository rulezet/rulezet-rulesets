rule TTP_XOR_WriteProcessMemory_1707 {
  strings:
    $key_1707 = { 40 75 [2] 72 57 [2] 74 62 [2] 5a 62 [2] 65 7e }

  condition:
    any of them
}