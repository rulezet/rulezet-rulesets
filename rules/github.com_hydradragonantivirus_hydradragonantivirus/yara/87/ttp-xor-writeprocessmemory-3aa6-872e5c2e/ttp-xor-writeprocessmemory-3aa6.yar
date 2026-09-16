rule TTP_XOR_WriteProcessMemory_3aa6 {
  strings:
    $key_3aa6 = { 6d d4 [2] 5f f6 [2] 59 c3 [2] 77 c3 [2] 48 df }

  condition:
    any of them
}