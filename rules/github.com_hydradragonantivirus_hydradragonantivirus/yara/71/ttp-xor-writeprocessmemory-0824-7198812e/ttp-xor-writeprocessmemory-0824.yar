rule TTP_XOR_WriteProcessMemory_0824 {
  strings:
    $key_0824 = { 5f 56 [2] 6d 74 [2] 6b 41 [2] 45 41 [2] 7a 5d }

  condition:
    any of them
}