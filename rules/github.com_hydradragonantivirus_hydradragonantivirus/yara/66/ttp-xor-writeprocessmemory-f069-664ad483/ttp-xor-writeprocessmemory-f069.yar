rule TTP_XOR_WriteProcessMemory_f069 {
  strings:
    $key_f069 = { a7 1b [2] 95 39 [2] 93 0c [2] bd 0c [2] 82 10 }

  condition:
    any of them
}