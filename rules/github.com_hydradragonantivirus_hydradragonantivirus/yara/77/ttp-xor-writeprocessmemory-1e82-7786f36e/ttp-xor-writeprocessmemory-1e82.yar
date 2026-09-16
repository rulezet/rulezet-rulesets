rule TTP_XOR_WriteProcessMemory_1e82 {
  strings:
    $key_1e82 = { 49 f0 [2] 7b d2 [2] 7d e7 [2] 53 e7 [2] 6c fb }

  condition:
    any of them
}