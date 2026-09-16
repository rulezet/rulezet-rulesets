rule TTP_XOR_WriteProcessMemory_1ca5 {
  strings:
    $key_1ca5 = { 4b d7 [2] 79 f5 [2] 7f c0 [2] 51 c0 [2] 6e dc }

  condition:
    any of them
}