rule TTP_XOR_WriteProcessMemory_e771 {
  strings:
    $key_e771 = { b0 03 [2] 82 21 [2] 84 14 [2] aa 14 [2] 95 08 }

  condition:
    any of them
}