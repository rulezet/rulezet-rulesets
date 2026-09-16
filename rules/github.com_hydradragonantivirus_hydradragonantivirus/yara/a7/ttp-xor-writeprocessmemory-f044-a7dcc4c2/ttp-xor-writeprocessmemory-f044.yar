rule TTP_XOR_WriteProcessMemory_f044 {
  strings:
    $key_f044 = { a7 36 [2] 95 14 [2] 93 21 [2] bd 21 [2] 82 3d }

  condition:
    any of them
}