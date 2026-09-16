rule TTP_XOR_WriteProcessMemory_1f13 {
  strings:
    $key_1f13 = { 48 61 [2] 7a 43 [2] 7c 76 [2] 52 76 [2] 6d 6a }

  condition:
    any of them
}