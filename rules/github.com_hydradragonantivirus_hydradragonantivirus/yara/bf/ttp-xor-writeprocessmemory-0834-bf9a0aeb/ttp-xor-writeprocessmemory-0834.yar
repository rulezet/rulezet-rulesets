rule TTP_XOR_WriteProcessMemory_0834 {
  strings:
    $key_0834 = { 5f 46 [2] 6d 64 [2] 6b 51 [2] 45 51 [2] 7a 4d }

  condition:
    any of them
}