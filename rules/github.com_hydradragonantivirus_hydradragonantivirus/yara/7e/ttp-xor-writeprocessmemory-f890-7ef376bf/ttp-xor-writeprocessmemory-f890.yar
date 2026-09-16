rule TTP_XOR_WriteProcessMemory_f890 {
  strings:
    $key_f890 = { af e2 [2] 9d c0 [2] 9b f5 [2] b5 f5 [2] 8a e9 }

  condition:
    any of them
}