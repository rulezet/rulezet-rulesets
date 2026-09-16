rule TTP_XOR_WriteProcessMemory_3e43 {
  strings:
    $key_3e43 = { 69 31 [2] 5b 13 [2] 5d 26 [2] 73 26 [2] 4c 3a }

  condition:
    any of them
}