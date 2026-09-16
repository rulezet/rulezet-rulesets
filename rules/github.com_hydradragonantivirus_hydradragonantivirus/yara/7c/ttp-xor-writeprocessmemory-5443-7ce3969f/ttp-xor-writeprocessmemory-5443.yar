rule TTP_XOR_WriteProcessMemory_5443 {
  strings:
    $key_5443 = { 03 31 [2] 31 13 [2] 37 26 [2] 19 26 [2] 26 3a }

  condition:
    any of them
}