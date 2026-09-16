rule TTP_XOR_WriteProcessMemory_f8a5 {
  strings:
    $key_f8a5 = { af d7 [2] 9d f5 [2] 9b c0 [2] b5 c0 [2] 8a dc }

  condition:
    any of them
}