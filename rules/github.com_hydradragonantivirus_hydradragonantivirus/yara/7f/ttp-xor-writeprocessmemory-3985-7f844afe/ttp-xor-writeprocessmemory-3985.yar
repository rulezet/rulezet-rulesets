rule TTP_XOR_WriteProcessMemory_3985 {
  strings:
    $key_3985 = { 6e f7 [2] 5c d5 [2] 5a e0 [2] 74 e0 [2] 4b fc }

  condition:
    any of them
}