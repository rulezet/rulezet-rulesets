rule TTP_XOR_WriteProcessMemory_0ca5 {
  strings:
    $key_0ca5 = { 5b d7 [2] 69 f5 [2] 6f c0 [2] 41 c0 [2] 7e dc }

  condition:
    any of them
}