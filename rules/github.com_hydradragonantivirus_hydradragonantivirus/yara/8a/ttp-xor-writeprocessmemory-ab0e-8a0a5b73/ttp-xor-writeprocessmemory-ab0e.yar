rule TTP_XOR_WriteProcessMemory_ab0e {
  strings:
    $key_ab0e = { fc 7c [2] ce 5e [2] c8 6b [2] e6 6b [2] d9 77 }

  condition:
    any of them
}