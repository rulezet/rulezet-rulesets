rule TTP_XOR_WriteProcessMemory_1f43 {
  strings:
    $key_1f43 = { 48 31 [2] 7a 13 [2] 7c 26 [2] 52 26 [2] 6d 3a }

  condition:
    any of them
}