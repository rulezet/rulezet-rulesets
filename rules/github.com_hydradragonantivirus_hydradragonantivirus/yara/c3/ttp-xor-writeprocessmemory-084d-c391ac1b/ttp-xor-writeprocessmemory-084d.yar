rule TTP_XOR_WriteProcessMemory_084d {
  strings:
    $key_084d = { 5f 3f [2] 6d 1d [2] 6b 28 [2] 45 28 [2] 7a 34 }

  condition:
    any of them
}