rule TTP_XOR_WriteProcessMemory_3263 {
  strings:
    $key_3263 = { 65 11 [2] 57 33 [2] 51 06 [2] 7f 06 [2] 40 1a }

  condition:
    any of them
}