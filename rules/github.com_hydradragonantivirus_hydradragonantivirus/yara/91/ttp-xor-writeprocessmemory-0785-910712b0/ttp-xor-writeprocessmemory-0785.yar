rule TTP_XOR_WriteProcessMemory_0785 {
  strings:
    $key_0785 = { 50 f7 [2] 62 d5 [2] 64 e0 [2] 4a e0 [2] 75 fc }

  condition:
    any of them
}