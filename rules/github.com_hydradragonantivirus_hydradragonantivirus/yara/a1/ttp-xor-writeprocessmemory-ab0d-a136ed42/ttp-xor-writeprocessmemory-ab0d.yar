rule TTP_XOR_WriteProcessMemory_ab0d {
  strings:
    $key_ab0d = { fc 7f [2] ce 5d [2] c8 68 [2] e6 68 [2] d9 74 }

  condition:
    any of them
}