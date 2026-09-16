rule TTP_XOR_WriteProcessMemory_7fd0 {
  strings:
    $key_7fd0 = { 28 a2 [2] 1a 80 [2] 1c b5 [2] 32 b5 [2] 0d a9 }

  condition:
    any of them
}