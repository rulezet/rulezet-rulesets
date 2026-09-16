rule TTP_XOR_WriteProcessMemory_0864 {
  strings:
    $key_0864 = { 5f 16 [2] 6d 34 [2] 6b 01 [2] 45 01 [2] 7a 1d }

  condition:
    any of them
}