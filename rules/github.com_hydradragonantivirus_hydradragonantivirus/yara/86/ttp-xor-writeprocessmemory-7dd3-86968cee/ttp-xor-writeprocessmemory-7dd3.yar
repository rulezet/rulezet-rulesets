rule TTP_XOR_WriteProcessMemory_7dd3 {
  strings:
    $key_7dd3 = { 2a a1 [2] 18 83 [2] 1e b6 [2] 30 b6 [2] 0f aa }

  condition:
    any of them
}