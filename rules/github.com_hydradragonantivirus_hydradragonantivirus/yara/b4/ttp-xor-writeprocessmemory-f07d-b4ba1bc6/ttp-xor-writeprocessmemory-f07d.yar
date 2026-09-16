rule TTP_XOR_WriteProcessMemory_f07d {
  strings:
    $key_f07d = { a7 0f [2] 95 2d [2] 93 18 [2] bd 18 [2] 82 04 }

  condition:
    any of them
}