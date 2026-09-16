rule TTP_XOR_WriteProcessMemory_ab7c {
  strings:
    $key_ab7c = { fc 0e [2] ce 2c [2] c8 19 [2] e6 19 [2] d9 05 }

  condition:
    any of them
}