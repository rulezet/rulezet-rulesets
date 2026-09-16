rule TTP_XOR_WriteProcessMemory_29c2 {
  strings:
    $key_29c2 = { 7e b0 [2] 4c 92 [2] 4a a7 [2] 64 a7 [2] 5b bb }

  condition:
    any of them
}