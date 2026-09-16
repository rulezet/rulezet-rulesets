rule TTP_XOR_WriteProcessMemory_cba6 {
  strings:
    $key_cba6 = { 9c d4 [2] ae f6 [2] a8 c3 [2] 86 c3 [2] b9 df }

  condition:
    any of them
}