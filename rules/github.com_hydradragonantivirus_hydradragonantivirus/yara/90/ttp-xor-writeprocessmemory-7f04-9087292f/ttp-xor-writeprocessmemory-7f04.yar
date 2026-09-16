rule TTP_XOR_WriteProcessMemory_7f04 {
  strings:
    $key_7f04 = { 28 76 [2] 1a 54 [2] 1c 61 [2] 32 61 [2] 0d 7d }

  condition:
    any of them
}