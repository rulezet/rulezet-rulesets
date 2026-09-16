rule TTP_XOR_WriteProcessMemory_7ca5 {
  strings:
    $key_7ca5 = { 2b d7 [2] 19 f5 [2] 1f c0 [2] 31 c0 [2] 0e dc }

  condition:
    any of them
}