rule TTP_XOR_WriteProcessMemory_e772 {
  strings:
    $key_e772 = { b0 00 [2] 82 22 [2] 84 17 [2] aa 17 [2] 95 0b }

  condition:
    any of them
}