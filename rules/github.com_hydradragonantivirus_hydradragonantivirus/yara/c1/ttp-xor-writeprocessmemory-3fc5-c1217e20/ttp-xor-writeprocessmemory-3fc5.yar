rule TTP_XOR_WriteProcessMemory_3fc5 {
  strings:
    $key_3fc5 = { 68 b7 [2] 5a 95 [2] 5c a0 [2] 72 a0 [2] 4d bc }

  condition:
    any of them
}