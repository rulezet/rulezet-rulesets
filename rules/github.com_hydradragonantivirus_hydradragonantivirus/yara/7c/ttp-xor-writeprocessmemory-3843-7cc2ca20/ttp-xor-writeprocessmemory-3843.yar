rule TTP_XOR_WriteProcessMemory_3843 {
  strings:
    $key_3843 = { 6f 31 [2] 5d 13 [2] 5b 26 [2] 75 26 [2] 4a 3a }

  condition:
    any of them
}