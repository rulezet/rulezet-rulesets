rule TTP_XOR_WriteProcessMemory_1f74 {
  strings:
    $key_1f74 = { 48 06 [2] 7a 24 [2] 7c 11 [2] 52 11 [2] 6d 0d }

  condition:
    any of them
}