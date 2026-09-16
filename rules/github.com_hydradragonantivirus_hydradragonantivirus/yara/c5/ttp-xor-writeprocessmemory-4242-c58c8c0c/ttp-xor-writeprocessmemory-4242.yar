rule TTP_XOR_WriteProcessMemory_4242 {
  strings:
    $key_4242 = { 15 30 [2] 27 12 [2] 21 27 [2] 0f 27 [2] 30 3b }

  condition:
    any of them
}