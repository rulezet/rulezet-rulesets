rule TTP_XOR_WriteProcessMemory_05a6 {
  strings:
    $key_05a6 = { 52 d4 [2] 60 f6 [2] 66 c3 [2] 48 c3 [2] 77 df }

  condition:
    any of them
}