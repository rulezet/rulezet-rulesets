rule TTP_XOR_WriteProcessMemory_2890 {
  strings:
    $key_2890 = { 7f e2 [2] 4d c0 [2] 4b f5 [2] 65 f5 [2] 5a e9 }

  condition:
    any of them
}