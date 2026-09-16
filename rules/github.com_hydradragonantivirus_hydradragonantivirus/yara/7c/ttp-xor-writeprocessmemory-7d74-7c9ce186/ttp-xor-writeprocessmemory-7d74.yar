rule TTP_XOR_WriteProcessMemory_7d74 {
  strings:
    $key_7d74 = { 2a 06 [2] 18 24 [2] 1e 11 [2] 30 11 [2] 0f 0d }

  condition:
    any of them
}