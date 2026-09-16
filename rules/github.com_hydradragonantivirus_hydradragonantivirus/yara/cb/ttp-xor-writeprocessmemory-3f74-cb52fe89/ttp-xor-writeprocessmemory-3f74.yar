rule TTP_XOR_WriteProcessMemory_3f74 {
  strings:
    $key_3f74 = { 68 06 [2] 5a 24 [2] 5c 11 [2] 72 11 [2] 4d 0d }

  condition:
    any of them
}