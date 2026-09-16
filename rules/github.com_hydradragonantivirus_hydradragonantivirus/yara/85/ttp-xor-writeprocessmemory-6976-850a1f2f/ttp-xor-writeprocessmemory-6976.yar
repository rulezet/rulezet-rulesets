rule TTP_XOR_WriteProcessMemory_6976 {
  strings:
    $key_6976 = { 3e 04 [2] 0c 26 [2] 0a 13 [2] 24 13 [2] 1b 0f }

  condition:
    any of them
}