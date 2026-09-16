rule TTP_XOR_WriteProcessMemory_f056 {
  strings:
    $key_f056 = { a7 24 [2] 95 06 [2] 93 33 [2] bd 33 [2] 82 2f }

  condition:
    any of them
}