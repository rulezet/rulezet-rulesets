rule TTP_XOR_WriteProcessMemory_f02a {
  strings:
    $key_f02a = { a7 58 [2] 95 7a [2] 93 4f [2] bd 4f [2] 82 53 }

  condition:
    any of them
}