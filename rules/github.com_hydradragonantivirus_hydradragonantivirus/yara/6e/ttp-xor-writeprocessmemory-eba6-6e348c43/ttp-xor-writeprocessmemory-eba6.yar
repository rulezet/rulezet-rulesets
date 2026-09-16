rule TTP_XOR_WriteProcessMemory_eba6 {
  strings:
    $key_eba6 = { bc d4 [2] 8e f6 [2] 88 c3 [2] a6 c3 [2] 99 df }

  condition:
    any of them
}