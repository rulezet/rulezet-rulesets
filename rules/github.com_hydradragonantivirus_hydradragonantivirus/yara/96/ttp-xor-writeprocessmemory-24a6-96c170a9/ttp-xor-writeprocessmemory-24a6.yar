rule TTP_XOR_WriteProcessMemory_24a6 {
  strings:
    $key_24a6 = { 73 d4 [2] 41 f6 [2] 47 c3 [2] 69 c3 [2] 56 df }

  condition:
    any of them
}