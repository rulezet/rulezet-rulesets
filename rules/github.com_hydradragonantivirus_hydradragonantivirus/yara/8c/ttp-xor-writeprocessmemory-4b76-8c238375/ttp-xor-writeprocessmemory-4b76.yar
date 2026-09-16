rule TTP_XOR_WriteProcessMemory_4b76 {
  strings:
    $key_4b76 = { 1c 04 [2] 2e 26 [2] 28 13 [2] 06 13 [2] 39 0f }

  condition:
    any of them
}