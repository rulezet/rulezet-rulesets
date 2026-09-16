rule TTP_XOR_WriteProcessMemory_ab3e {
  strings:
    $key_ab3e = { fc 4c [2] ce 6e [2] c8 5b [2] e6 5b [2] d9 47 }

  condition:
    any of them
}