rule TTP_XOR_WriteProcessMemory_7aa6 {
  strings:
    $key_7aa6 = { 2d d4 [2] 1f f6 [2] 19 c3 [2] 37 c3 [2] 08 df }

  condition:
    any of them
}