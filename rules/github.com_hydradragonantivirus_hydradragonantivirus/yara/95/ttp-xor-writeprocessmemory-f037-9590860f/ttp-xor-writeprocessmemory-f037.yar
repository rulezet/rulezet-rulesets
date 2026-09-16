rule TTP_XOR_WriteProcessMemory_f037 {
  strings:
    $key_f037 = { a7 45 [2] 95 67 [2] 93 52 [2] bd 52 [2] 82 4e }

  condition:
    any of them
}