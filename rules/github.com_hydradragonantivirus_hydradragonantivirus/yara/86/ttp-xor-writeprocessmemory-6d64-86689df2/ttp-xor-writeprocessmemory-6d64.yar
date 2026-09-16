rule TTP_XOR_WriteProcessMemory_6d64 {
  strings:
    $key_6d64 = { 3a 16 [2] 08 34 [2] 0e 01 [2] 20 01 [2] 1f 1d }

  condition:
    any of them
}