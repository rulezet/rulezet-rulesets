rule TTP_XOR_WriteProcessMemory_0e64 {
  strings:
    $key_0e64 = { 59 16 [2] 6b 34 [2] 6d 01 [2] 43 01 [2] 7c 1d }

  condition:
    any of them
}