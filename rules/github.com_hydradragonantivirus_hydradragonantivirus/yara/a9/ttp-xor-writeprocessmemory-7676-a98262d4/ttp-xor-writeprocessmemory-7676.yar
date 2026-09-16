rule TTP_XOR_WriteProcessMemory_7676 {
  strings:
    $key_7676 = { 21 04 [2] 13 26 [2] 15 13 [2] 3b 13 [2] 04 0f }

  condition:
    any of them
}