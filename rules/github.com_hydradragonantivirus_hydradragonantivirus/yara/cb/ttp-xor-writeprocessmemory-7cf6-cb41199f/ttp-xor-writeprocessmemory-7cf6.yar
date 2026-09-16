rule TTP_XOR_WriteProcessMemory_7cf6 {
  strings:
    $key_7cf6 = { 2b 84 [2] 19 a6 [2] 1f 93 [2] 31 93 [2] 0e 8f }

  condition:
    any of them
}