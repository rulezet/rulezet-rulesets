rule TTP_XOR_WriteProcessMemory_ab5b {
  strings:
    $key_ab5b = { fc 29 [2] ce 0b [2] c8 3e [2] e6 3e [2] d9 22 }

  condition:
    any of them
}