rule TTP_XOR_WriteProcessMemory_2aa6 {
  strings:
    $key_2aa6 = { 7d d4 [2] 4f f6 [2] 49 c3 [2] 67 c3 [2] 58 df }

  condition:
    any of them
}