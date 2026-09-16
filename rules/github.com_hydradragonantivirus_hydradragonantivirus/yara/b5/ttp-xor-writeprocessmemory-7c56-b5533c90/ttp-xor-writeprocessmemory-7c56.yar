rule TTP_XOR_WriteProcessMemory_7c56 {
  strings:
    $key_7c56 = { 2b 24 [2] 19 06 [2] 1f 33 [2] 31 33 [2] 0e 2f }

  condition:
    any of them
}