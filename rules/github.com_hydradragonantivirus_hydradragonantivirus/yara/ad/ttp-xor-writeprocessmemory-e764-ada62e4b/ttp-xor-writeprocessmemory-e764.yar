rule TTP_XOR_WriteProcessMemory_e764 {
  strings:
    $key_e764 = { b0 16 [2] 82 34 [2] 84 01 [2] aa 01 [2] 95 1d }

  condition:
    any of them
}