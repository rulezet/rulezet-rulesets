rule TTP_XOR_WriteProcessMemory_f892 {
  strings:
    $key_f892 = { af e0 [2] 9d c2 [2] 9b f7 [2] b5 f7 [2] 8a eb }

  condition:
    any of them
}