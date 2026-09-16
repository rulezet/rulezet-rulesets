rule TTP_XOR_WriteProcessMemory_e770 {
  strings:
    $key_e770 = { b0 02 [2] 82 20 [2] 84 15 [2] aa 15 [2] 95 09 }

  condition:
    any of them
}