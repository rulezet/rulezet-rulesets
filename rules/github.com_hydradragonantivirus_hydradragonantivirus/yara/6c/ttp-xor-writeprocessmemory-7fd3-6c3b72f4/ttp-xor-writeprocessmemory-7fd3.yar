rule TTP_XOR_WriteProcessMemory_7fd3 {
  strings:
    $key_7fd3 = { 28 a1 [2] 1a 83 [2] 1c b6 [2] 32 b6 [2] 0d aa }

  condition:
    any of them
}