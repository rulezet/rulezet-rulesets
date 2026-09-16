rule TTP_XOR_WriteProcessMemory_0e04 {
  strings:
    $key_0e04 = { 59 76 [2] 6b 54 [2] 6d 61 [2] 43 61 [2] 7c 7d }

  condition:
    any of them
}