rule TTP_XOR_WriteProcessMemory_e676 {
  strings:
    $key_e676 = { b1 04 [2] 83 26 [2] 85 13 [2] ab 13 [2] 94 0f }

  condition:
    any of them
}