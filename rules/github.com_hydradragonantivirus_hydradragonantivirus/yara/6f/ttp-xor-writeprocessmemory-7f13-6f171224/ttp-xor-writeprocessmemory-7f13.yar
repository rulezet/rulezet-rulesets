rule TTP_XOR_WriteProcessMemory_7f13 {
  strings:
    $key_7f13 = { 28 61 [2] 1a 43 [2] 1c 76 [2] 32 76 [2] 0d 6a }

  condition:
    any of them
}