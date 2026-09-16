rule TTP_XOR_WriteProcessMemory_ab7b {
  strings:
    $key_ab7b = { fc 09 [2] ce 2b [2] c8 1e [2] e6 1e [2] d9 02 }

  condition:
    any of them
}