rule TTP_XOR_WriteProcessMemory_f8a6 {
  strings:
    $key_f8a6 = { af d4 [2] 9d f6 [2] 9b c3 [2] b5 c3 [2] 8a df }

  condition:
    any of them
}