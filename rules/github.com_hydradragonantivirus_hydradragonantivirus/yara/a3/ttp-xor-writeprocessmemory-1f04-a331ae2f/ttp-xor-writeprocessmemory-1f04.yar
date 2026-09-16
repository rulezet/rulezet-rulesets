rule TTP_XOR_WriteProcessMemory_1f04 {
  strings:
    $key_1f04 = { 48 76 [2] 7a 54 [2] 7c 61 [2] 52 61 [2] 6d 7d }

  condition:
    any of them
}