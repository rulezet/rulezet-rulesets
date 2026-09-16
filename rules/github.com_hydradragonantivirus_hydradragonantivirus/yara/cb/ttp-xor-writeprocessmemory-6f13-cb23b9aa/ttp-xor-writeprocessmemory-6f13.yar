rule TTP_XOR_WriteProcessMemory_6f13 {
  strings:
    $key_6f13 = { 38 61 [2] 0a 43 [2] 0c 76 [2] 22 76 [2] 1d 6a }

  condition:
    any of them
}