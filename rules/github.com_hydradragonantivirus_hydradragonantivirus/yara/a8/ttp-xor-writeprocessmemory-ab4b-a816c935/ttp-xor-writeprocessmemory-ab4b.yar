rule TTP_XOR_WriteProcessMemory_ab4b {
  strings:
    $key_ab4b = { fc 39 [2] ce 1b [2] c8 2e [2] e6 2e [2] d9 32 }

  condition:
    any of them
}