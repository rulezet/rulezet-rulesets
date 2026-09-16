rule TTP_XOR_WriteProcessMemory_6c56 {
  strings:
    $key_6c56 = { 3b 24 [2] 09 06 [2] 0f 33 [2] 21 33 [2] 1e 2f }

  condition:
    any of them
}