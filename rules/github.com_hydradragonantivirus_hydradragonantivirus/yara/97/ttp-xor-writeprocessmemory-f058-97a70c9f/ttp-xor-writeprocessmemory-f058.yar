rule TTP_XOR_WriteProcessMemory_f058 {
  strings:
    $key_f058 = { a7 2a [2] 95 08 [2] 93 3d [2] bd 3d [2] 82 21 }

  condition:
    any of them
}