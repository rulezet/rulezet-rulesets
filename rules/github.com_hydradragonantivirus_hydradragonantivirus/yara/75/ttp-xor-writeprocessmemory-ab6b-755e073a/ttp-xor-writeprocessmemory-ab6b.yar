rule TTP_XOR_WriteProcessMemory_ab6b {
  strings:
    $key_ab6b = { fc 19 [2] ce 3b [2] c8 0e [2] e6 0e [2] d9 12 }

  condition:
    any of them
}