rule TTP_XOR_WriteProcessMemory_ab3c {
  strings:
    $key_ab3c = { fc 4e [2] ce 6c [2] c8 59 [2] e6 59 [2] d9 45 }

  condition:
    any of them
}