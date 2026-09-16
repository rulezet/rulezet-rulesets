rule TTP_XOR_WriteProcessMemory_4443 {
  strings:
    $key_4443 = { 13 31 [2] 21 13 [2] 27 26 [2] 09 26 [2] 36 3a }

  condition:
    any of them
}