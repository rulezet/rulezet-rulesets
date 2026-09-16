rule TTP_XOR_WriteProcessMemory_28a5 {
  strings:
    $key_28a5 = { 7f d7 [2] 4d f5 [2] 4b c0 [2] 65 c0 [2] 5a dc }

  condition:
    any of them
}