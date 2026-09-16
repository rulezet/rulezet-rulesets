rule TTP_XOR_WriteProcessMemory_f023 {
  strings:
    $key_f023 = { a7 51 [2] 95 73 [2] 93 46 [2] bd 46 [2] 82 5a }

  condition:
    any of them
}