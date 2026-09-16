rule TTP_XOR_WriteProcessMemory_503b {
  strings:
    $key_503b = { 07 49 [2] 35 6b [2] 33 5e [2] 1d 5e [2] 22 42 }

  condition:
    any of them
}