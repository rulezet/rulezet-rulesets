rule TTP_XOR_WriteProcessMemory_ab0c {
  strings:
    $key_ab0c = { fc 7e [2] ce 5c [2] c8 69 [2] e6 69 [2] d9 75 }

  condition:
    any of them
}